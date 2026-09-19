//! Command-line interface front end for Tradr (DCR-124).

use std::path::PathBuf;
use std::sync::Arc;

use tradr_app::identity::{
    OsRng, describe_backing, open_device_identity, platform_ladder, storage_level_name,
};
use tradr_app::paths::{app_data_dir, device_keys_dir};
use tradr_app::receive::{RelPath, run_receive};
use tradr_app::send_session::{TransferProgressPayload, discover_peers, run_send};
use tradr_app::sign_in::OAuthConfig;

fn print_usage() {
    eprintln!(
        "usage: tradr-cli <command>\n\ncommands:\n  device     Report this device's identity\n  peers      Discover and list peers\n  receive    Receive files into a directory\n  send       Send files to a peer"
    );
}

fn run_device() -> Result<(), String> {
    let dir = app_data_dir()?;
    let keys_dir = device_keys_dir(&dir);
    let ladder = platform_ladder(keys_dir);
    let identity = open_device_identity(&ladder, &OsRng)?;

    let (backing, reason) = describe_backing(identity.backing());
    let backing_line = match reason {
        Some(r) => format!("{backing} ({r})"),
        None => backing.to_string(),
    };

    println!("device id  {}", identity.public_identity().device_id());
    println!("backing    {backing_line}");
    println!(
        "storage    {}",
        storage_level_name(identity.storage_level())
    );
    Ok(())
}

async fn run_peers_command() -> Result<(), String> {
    let peers = discover_peers().await?;
    if peers.is_empty() {
        eprintln!("tradr-cli: no peers found");
        return Ok(());
    }
    for (i, peer) in peers.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("key        {}", peer.key);
        if let Some(name) = &peer.display_name {
            println!("name       {name}");
        }
        println!("addresses  {}", peer.addresses.join(", "));
        println!("sources    {}", peer.sources.join(", "));
    }
    Ok(())
}

async fn run_receive_command(dir_arg: Option<String>) -> Result<(), String> {
    let receive_dir = match dir_arg {
        Some(d) => PathBuf::from(d),
        None => dirs::download_dir()
            .ok_or_else(|| "could not resolve download directory".to_string())?,
    };
    let oauth = OAuthConfig::from_env();
    let on_arrival = Arc::new(|paths: &[RelPath]| {
        for path in paths {
            println!("{path}");
        }
    });
    run_receive(receive_dir, &oauth, on_arrival).await
}

async fn run_send_command(peer: &str, files: &[String]) -> Result<(), String> {
    let oauth = OAuthConfig::from_env();
    let on_progress =
        Arc::new(
            |progress: &TransferProgressPayload| match progress.status.as_str() {
                "starting" => {
                    println!(
                        "starting {} ({} bytes)",
                        progress.rel_path, progress.total_bytes
                    );
                }
                "completed" => {
                    println!("sent {}", progress.rel_path);
                }
                "failed" => {
                    println!("failed {}", progress.rel_path);
                }
                _ => {}
            },
        );
    let placed = run_send(peer, files, &oauth, on_progress).await?;
    eprintln!("{} of {} items placed", placed.len(), files.len());
    Ok(())
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("device") => {
            if args.next().is_some() {
                print_usage();
                std::process::exit(2);
            }
            if let Err(e) = run_device() {
                eprintln!("tradr-cli: {e}");
                std::process::exit(1);
            }
        }
        Some("peers") => {
            if args.next().is_some() {
                print_usage();
                std::process::exit(2);
            }
            if let Err(e) = run_peers_command().await {
                eprintln!("tradr-cli: {e}");
                std::process::exit(1);
            }
        }
        Some("receive") => {
            let dir_arg = args.next();
            if args.next().is_some() {
                print_usage();
                std::process::exit(2);
            }
            if let Err(e) = run_receive_command(dir_arg).await {
                eprintln!("tradr-cli: {e}");
                std::process::exit(1);
            }
        }
        Some("send") => {
            let peer = match args.next() {
                Some(p) => p,
                None => {
                    print_usage();
                    std::process::exit(2);
                }
            };
            let files: Vec<String> = args.collect();
            if files.is_empty() {
                print_usage();
                std::process::exit(2);
            }
            if let Err(e) = run_send_command(&peer, &files).await {
                eprintln!("tradr-cli: {e}");
                std::process::exit(1);
            }
        }
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }
}
