use azure_iot_sdk::{DeviceKeyTokenSource, TokenSource, IoTHubClient, MessageType, message::Message};

use clap::{App, Arg};
use env_logger;
use chrono;
use reqwest;
use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::json;
use std::env;
use std::fs;
use std::io::prelude::*;
use std::process;
use std::panic;

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct AzureREST {
    #[serde(default)]
    pub correlationId: String,
    #[serde(default)]
    pub hostName: String,
    #[serde(default)]
    pub containerName: String,
    #[serde(default)]
    pub blobName: String,
    #[serde(default)]
    pub sasToken: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Parse command line arguments
    let args = App::new("azure-iothub")
        // headers
        .version(env!("CARGO_PKG_VERSION"))
        .author("ADVALY SYSTEM Inc.")
        .about("Azure IoT-Hub message client and file uploader")

        // subcommand: sas
        .subcommand(App::new("sas")
            .about("Show SAS token and exit")
        )

        // subcommand: c2d
        .subcommand(App::new("c2d")
            .about("Cloud to device message listner")
            .after_help("The process will exit with eixt code 9 when no ping response from server.")
            .arg(Arg::with_name("callback")
                .short("c").long("callback-command")
                .help("Callback command on c2d message. \
                    stdout of the command is sent to cloud as device message")
                .required(true)
                .takes_value(true)
            )
        )

        // subcommand: d2c
        .subcommand(App::new("d2c")
            .about("Send a device to cloud message")
            .arg(Arg::with_name("body")
                .short("b").long("body")
                .help("Send a device message to cloud")
                .required(true)
                .takes_value(true)
            )
        )

        // subcommand: upload
        .subcommand(App::new("upload")
            .about("File upload")
            .arg(Arg::with_name("upload file")
                .short("f").long("upload-file")
                .help("Local path of the uploading file")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("blob name")
                .short("b").long("blob-name")
                .help("Storage blob name")
                .required(true)
                .takes_value(true)
            )
        )

        // subcommand: download
        .subcommand(App::new("download")
            .about("File download")
            .arg(Arg::with_name("download file")
                .short("f").long("download-file")
                .help("Local path of the download file")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("blob name")
                .short("b").long("blob-name")
                .help("Storage blob name")
                .required(true)
                .takes_value(true)
            )
        )

        // options
        .arg(Arg::with_name("iothub name")
           .short("n").long("name")
            .help("IoT-Hub name")
            .required(true)
            .takes_value(true)
        )
        .arg(Arg::with_name("device id")
           .short("i").long("device-id")
            .help("Device ID")
            .required(true)
            .takes_value(true)
        )
        .arg(Arg::with_name("shared access key")
           .short("s").long("shared-access-key")
            .help("Shared Access Key. \
                The SHARED_ACCESS_KEY environment variable is used \
                for shared access key if this option was ommited")
            .takes_value(true)
        )
        .get_matches();

    let hostname = args.value_of("iothub name").unwrap().to_string() + ".azure-devices.net";
    let device_id = args.value_of("device id").unwrap();
    let shared_access_key = match args.value_of("shared access key") {
        Some(s) => s.to_string(),
        _ => std::env::var("SHARED_ACCESS_KEY").expect("SHARED_ACCESS_KEY is not defined")
    };

    // Token
    let token_source =
        DeviceKeyTokenSource::new(&hostname, device_id, &shared_access_key).unwrap();
    let expiry = chrono::Utc::now() + chrono::Duration::days(1);
    let token = token_source.get(&expiry);

    // Run subcommand
    match args.subcommand() {
        // c2d
        ("c2d", Some(sub_m)) => {
            let callback = sub_m.value_of("callback").ok_or(anyhow!("No callback command specified"))?;
            let client =
                match IoTHubClient::new(&hostname, device_id.into(), token_source).await {
                    Ok(c) => c,
                    Err(e) => { return Err(anyhow!("{}", e)); }
                };
            c2d(callback, client).await?;
        },

        // d2c
        ("d2c", Some(sub_m)) => {
            let body = sub_m.value_of("body").unwrap();
            let client =
                match IoTHubClient::new(&hostname, device_id.into(), token_source).await {
                    Ok(c) => c,
                    Err(e) => { return Err(anyhow!("{}", e)); }
                };
            d2c(body, client).await?;
        },

        // Upload file
        ("upload", Some(sub_m)) => {
            let upload_file = sub_m.value_of("upload file").ok_or(anyhow!("No upload file specified"))?;
            let blob_name = sub_m.value_of("blob name").ok_or(anyhow!("No blob name specified"))?;
            upload(&upload_file, &blob_name, &token, &hostname, device_id).await?;
        },

        // Download file
        ("download", Some(sub_m)) => {
            let upload_file = sub_m.value_of("download file").ok_or(anyhow!("No download file specified"))?;
            let blob_name = sub_m.value_of("blob name").ok_or(anyhow!("No blob name specified"))?;
            download(&upload_file, &blob_name, &token, &hostname, device_id).await?;
        },

        // Show SAS token
        ("sas", Some(_)) => {
            println!("{}", token);
        },

        // Error
        _ => return Err(anyhow!("Invalid subcommand"))
    }

    Ok(())
}

/*
    Upload a file
 */
async fn upload(upload_file: &str, blobname: &str, sas_token: &str, hostname: &str, device_id: &str) -> Result<()>
{
    let client = reqwest::Client::new();

    // Load upload data
    let mut file = fs::File::open(upload_file)?;
    let mut body = Vec::new();
    file.read_to_end(&mut body)?;

    // 1. Init upload
    let res = client
        .post(format!("https://{}/devices/{}/files?api-version=2018-06-30", hostname, device_id))
        .header("Content-Type", "application/json")
        .header("Authorization", sas_token)
        .body(json!({"blobName": blobname}).to_string())
        .send()
        .await?;

    // Return here if failed
    if ! res.status().is_success() {
        return Err(anyhow!(response_msg(res).await?));
    }

    // Parse response data
    let v: AzureREST = serde_json::from_str(res.text().await?.as_str())?;
    println!("Upload to https://{}/{}/{}", v.hostName, v.containerName, v.blobName);

    // 2. Upload
    let res = client
        .put(format!("https://{}/{}/{}{}", v.hostName, v.containerName, v.blobName, v.sasToken))
        .header("x-ms-date", chrono::Utc::now().to_string())
        .header("x-ms-version", "2020-10-02")
        .header("x-ms-blob-type", "BlockBlob")
        .body(body)
        .send()
        .await?;

    let status = res.status().is_success();
    if ! status {
        eprintln!("{}", response_msg(res).await?);
    }

    // 3. Notify completion of upload
    let res = client
        .post(format!("https://{}/devices/{}/files/notifications?api-version=2018-06-30", hostname, device_id))
        .header("Content-Type", "application/json")
        .header("Authorization", sas_token)
        .body(json!({"correlationId": v.correlationId, "isSuccess": status}).to_string())
        .send()
        .await?;

    if ! res.status().is_success() {
        eprintln!("{}", response_msg(res).await?);
    }

    // Result code
    match status {
        true => Ok(()),
        false => Err(anyhow!("Upload failed"))
    }
}

/*
    Download a file
 */
async fn download(dst_file: &str, blobname: &str, sas_token: &str, hostname: &str, device_id: &str) -> Result<()>
{
    let client = reqwest::Client::new();

    // Open the local destination file
    let mut file = fs::File::create(dst_file)?;

    // 1. Init upload
    let res = client
        .post(format!("https://{}/devices/{}/files?api-version=2018-06-30", hostname, device_id))
        .header("Content-Type", "application/json")
        .header("Authorization", sas_token)
        .body(json!({"blobName": blobname}).to_string())
        .send()
        .await?;

    // Return here if failed
    if ! res.status().is_success() {
        return Err(anyhow!(response_msg(res).await?));
    }

    // Parse response data
    let v: AzureREST = serde_json::from_str(res.text().await?.as_str())?;
    println!("Download from https://{}/{}/{}", v.hostName, v.containerName, v.blobName);

    // 2. Download
    let res = client
        .get(format!("https://{}/{}/{}{}", v.hostName, v.containerName, v.blobName, v.sasToken))
        .header("x-ms-date", chrono::Utc::now().to_string())
        .header("x-ms-version", "2020-10-02")
        .header("x-ms-blob-type", "BlockBlob")
        .send()
        .await?;

    let status = res.status().is_success();
    if ! status {
        eprintln!("{}", response_msg(res).await?);
    } else {
        let data = res.bytes().await?;
        file.write_all(&data)?;
    }

    // 3. Notify completion of upload
    let res = client
        .post(format!("https://{}/devices/{}/files/notifications?api-version=2018-06-30", hostname, device_id))
        .header("Content-Type", "application/json")
        .header("Authorization", sas_token)
        .body(json!({"correlationId": v.correlationId, "isSuccess": status}).to_string())
        .send()
        .await?;

    if ! res.status().is_success() {
        eprintln!("{}", response_msg(res).await?);
    }

    // Result code
    match status {
        true => Ok(()),
        false => Err(anyhow!("Download failed"))
    }
}

/*
    C2D, Cloud to device message
 */
async fn c2d(callback: &str, mut client: IoTHubClient) -> Result<()>
{
    // Set panic handler
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Exit the process silently with exit code 9 at ping panic
        if let Some(msg) = panic_info.payload().downcast_ref::<&'static str>() {
            if *msg == "No ping response" {
                eprintln!("Exit: Keepalive failed");
                process::exit(9);
            }
        }
        // Invoke the default handler
        orig_hook(panic_info);
        process::exit(101);
    }));

    // Cloud to device message
    let mut recv = client.get_receiver().await;
    while let Some(cmsg) = recv.recv().await {
        match cmsg {
            MessageType::C2DMessage(msg) => {
                if let Ok(msg_str) = std::str::from_utf8(&msg.body) {
                    println!("Received: {}", msg_str);
                    let resstr = match process::Command::new(callback).arg(msg_str).output() {
                        Ok(output) => {
                            std::str::from_utf8(&output.stdout).unwrap_or("unwrap error").to_string()
                        },
                        Err(e) => { 
                            eprintln!("Error: {:?}", e);
                            String::from("command error")
                        }
                    };
                    d2c(resstr, client.clone()).await.unwrap_or(());
                }
            },
            _ => {}
        }
    }

    Ok(())
}

/*
    D2C, Device to cloud Message
 */
async fn d2c(body: impl Into<String>, mut client: IoTHubClient) -> Result<()>
{
    let body_string: String = body.into().trim().to_string();

    let msg = Message::builder()
        .set_body(body_string.as_bytes().to_vec())
        .set_content_type("application/json".to_owned())
        .set_content_encoding("utf-8".to_owned())
        .build();

    match client.send_message(msg).await {
        Ok(_) => {
            println!("Sent: body '{}'", body_string);
            Ok(())
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(anyhow!("{}", e))
        }
    }
}

/*
    Get print string from http response (for error)
 */
async fn response_msg(res: reqwest::Response) -> Result<String>
{
    Ok(format!("{} {}", res.status(), res.text().await?))
}
