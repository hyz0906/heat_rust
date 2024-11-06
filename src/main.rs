use anyhow::Result;
use chrono::{DateTime, Utc};
use kube::{
    api::{Api, ListParams},
    Client,
    config::{KubeConfigOptions, Kubeconfig},
};
use k8s_openapi::api::snapshot::v1::{VolumeSnapshot, VolumeSnapshotStatus};
use reqwest;
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use std::time::Duration;
use tokio_ssh2::AsyncSession;
use tokio::time::sleep;
use std::path::PathBuf;
use std::env;
mod encryption;
use encryption::PasswordEncryption;

#[derive(Debug, Serialize, Deserialize)]
struct CreateCodespaceRequest {
    tag_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateCodespaceResponse {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CodespaceStatus {
    status: String,
}

async fn get_newest_snapshot(client: Client) -> Result<Option<String>> {
    let snapshots: Api<VolumeSnapshot> = Api::all(client);
    let lp = ListParams::default();
    
    let snapshot_list = snapshots.list(&lp).await?;
    
    let newest_snapshot = snapshot_list
        .items
        .into_iter()
        .filter(|s| s.metadata.name.as_ref().map_or(false, |name| name.contains("abc")))
        .max_by_key(|s| {
            s.metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| DateTime::parse_from_rfc3339(&ts.0).unwrap())
        });

    Ok(newest_snapshot.and_then(|s| s.metadata.name))
}

async fn save_tag_to_db(pool: &MySqlPool, tag_name: &str) -> Result<()> {
    sqlx::query("INSERT INTO tag (name) VALUES (?)")
        .bind(tag_name)
        .execute(pool)
        .await?;
    Ok(())
}

async fn create_codespace(http_client: &reqwest::Client, tag_name: &str) -> Result<String> {
    let request = CreateCodespaceRequest {
        tag_name: tag_name.to_string(),
    };
    
    let response: CreateCodespaceResponse = http_client
        .post("http://your-service-url/api/create-codespace")
        .json(&request)
        .send()
        .await?
        .json()
        .await?;
    
    Ok(response.id)
}

async fn wait_for_codespace_ready(http_client: &reqwest::Client, codespace_id: &str) -> Result<()> {
    loop {
        let status: CodespaceStatus = http_client
            .get(&format!("http://your-service-url/api/codespace-status/{}", codespace_id))
            .send()
            .await?
            .json()
            .await?;
            
        if status.status == "success" {
            break;
        }
        
        sleep(Duration::from_secs(10)).await;
    }
    Ok(())
}

async fn execute_ssh_commands(
    host: &str, 
    username: &str, 
    encrypted_password: &str,
    password_encryption: &PasswordEncryption,
) -> Result<()> {
    let password = password_encryption.decrypt(encrypted_password)?;
    
    let tcp = tokio::net::TcpStream::connect(host).await?;
    let mut session = AsyncSession::new(tcp, None)?;
    
    session.handshake().await?;
    session.userauth_password(username, &password).await?;
    
    let mut channel = session.channel_session().await?;
    
    channel.exec("your_command_here").await?;
    
    let mut output = String::new();
    channel.read_to_string(&mut output).await?;
    println!("Command output: {}", output);
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let kubeconfig_path = env::var("KUBECONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/path/to/your/kubeconfig"));

    let kubeconfig = Kubeconfig::read_from(&kubeconfig_path)
        .map_err(|e| anyhow::anyhow!("Failed to read kubeconfig from {:?}: {}", kubeconfig_path, e))?;
    
    let config = kube::Config::from_custom_kubeconfig(
        kubeconfig,
        &KubeConfigOptions {
            context: env::var("KUBE_CONTEXT").ok(),
            cluster: env::var("KUBE_CLUSTER").ok(),
            user: env::var("KUBE_USER").ok(),
        },
    )
    .await?;
    
    let client = Client::try_from(config)?;
    
    let pool = MySqlPool::connect("mysql://user:password@localhost/dbname").await?;
    
    let http_client = reqwest::Client::new();
    
    let snapshot_name = get_newest_snapshot(client)
        .await?
        .ok_or_else(|| anyhow::anyhow!("No matching snapshot found"))?;
    
    save_tag_to_db(&pool, &snapshot_name).await?;
    
    let codespace_id = create_codespace(&http_client, &snapshot_name).await?;
    
    wait_for_codespace_ready(&http_client, &codespace_id).await?;
    
    let encryption_key = env::var("ENCRYPTION_KEY")
        .map_err(|_| anyhow::anyhow!("ENCRYPTION_KEY environment variable not set"))?;
    let encryption_nonce = env::var("ENCRYPTION_NONCE")
        .map_err(|_| anyhow::anyhow!("ENCRYPTION_NONCE environment variable not set"))?;

    let key_bytes = encryption::decode_base64(&encryption_key)?;
    let nonce_bytes = encryption::decode_base64(&encryption_nonce)?;

    let key: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
    let nonce: [u8; 12] = nonce_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid nonce length"))?;

    let password_encryption = PasswordEncryption::new(&key, &nonce);

    let encrypted_password = env::var("ENCRYPTED_SSH_PASSWORD")
        .map_err(|_| anyhow::anyhow!("ENCRYPTED_SSH_PASSWORD environment variable not set"))?;

    execute_ssh_commands(
        "your-codespace-host",
        "username",
        &encrypted_password,
        &password_encryption
    ).await?;
    
    Ok(())
}
