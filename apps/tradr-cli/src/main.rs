//! Command-line interface front end for Tradr (DCR-124).

use std::path::PathBuf;
use std::sync::Arc;

use tradr_app::identity::{
    OsRng, describe_backing, open_device_identity, platform_ladder, storage_level_name,
};
use tradr_app::paths::{app_data_dir, device_keys_dir};
use tradr_app::receive::{RelPath, run_receive};
use tradr_app::sign_in::OAuthConfig;

fn print_usage() {
    eprintln!(
        "usage: tradr-cli <command>\n\ncommands:\n  device     Report this device's identity\n  receive    Receive files into a directory"
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
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }
}
