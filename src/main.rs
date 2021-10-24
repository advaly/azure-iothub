use azure_iot_sdk::{DeviceKeyTokenSource, TokenSource, IoTHubClient, MessageType, message::Message};

use tokio::time::{sleep, Duration};
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
use std::str;
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
                .help("Callback command on c2d message")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("message")
                .short("m").long("message-file")
                .help("Watch file for message to cloud. \
                    A new massage will be sent when the contents of this file was changed")
                .takes_value(true)
            )
            .arg(Arg::with_name("interval")
                .short("i").long("interval")
                .help("Check intervel time in seconds of the message to cloud")
                .takes_value(true)
                .default_value("60")
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
            let message = sub_m.value_of("message").unwrap_or("");
            let interval = sub_m.value_of("interval").unwrap_or("60").parse::<u64>().unwrap_or(60);
            let client =
                match IoTHubClient::new(&hostname, device_id.into(), token_source).await {
                    Ok(c) => c,
                    Err(e) => { return Err(anyhow!("{}", e)); }
                };
            c2d(callback, message, interval, client).await?;
        },

        // Upload file
        ("upload", Some(sub_m)) => {
            let upload_file = sub_m.value_of("upload file").ok_or(anyhow!("No upload file specified"))?;
            let blob_name = sub_m.value_of("blob name").ok_or(anyhow!("No blob name specified"))?;
            upload(&upload_file, &blob_name, &token, &hostname, device_id).await?;
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
        return Err(anyhow!(res.text().await?.to_string()));
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
        eprintln!("{}", res.text().await?.to_string());
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
        eprintln!("{}", res.text().await?.to_string());
    }

    // Result code
    match status {
        true => Ok(()),
        false => Err(anyhow!("Upload failed"))
    }
}

/*
    C2D
 */
async fn c2d(callback: &str, dmsg_path: &str, interval: u64, mut client: IoTHubClient) -> Result<()>
{
    // Set panic handler
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Exit the process silently with exit code 9 at ping panic
        if let Some(msg) = panic_info.payload().downcast_ref::<&'static str>() {
            if *msg == "No ping response" {
                eprintln!("Exit: {}", *msg);
                process::exit(9);
            }
        }
        // Invoke the default handler
        orig_hook(panic_info);
        process::exit(101);
    }));

    // Cloud to device message
    let mut recv = client.get_receiver().await;
    let receive_loop = async {
        while let Some(cmsg) = recv.recv().await {
            match cmsg {
                MessageType::C2DMessage(msg) => {
                    if let Ok(msg_str) = str::from_utf8(&msg.body) {
                        println!("Received: {}", msg_str);
                        match process::Command::new(callback).arg(msg_str).spawn() {
                            Ok(_) => {},
                            Err(e) => { eprintln!("Error: {:?}", e) },
                        }
                    }
                },
                _ => {}
            }
        }
    };

    // Device to cloud message
    let send_loop = async {
        let mut dmsg = String::from("");
        loop {
            sleep(Duration::from_secs(interval)).await;

            // Read message from file
            let cur_msg = match fs::read_to_string(dmsg_path) {
                Ok(s) => s.trim().replace('\n', ""),
                Err(_) => continue
            };

            // Send if message is different from provious
            if dmsg != cur_msg {
                dmsg = cur_msg;
                let msg = Message::builder()
                    .set_body(vec![])
                    .add_message_property(String::from("message"), dmsg.clone())
                    .build();
                match client.send_message(msg).await {
                    Ok(_) => println!("Sent: {}", dmsg),
                    Err(e) => eprintln!("Error: {}", e)
                }
            }
        }
    };

    tokio::join!(receive_loop, send_loop);

    Ok(())
}