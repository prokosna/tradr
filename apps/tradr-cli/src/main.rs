//! Command-line interface front end for Tradr (DCR-124).

use tradr_app::identity::{
    OsRng, describe_backing, open_device_identity, platform_ladder, storage_level_name,
};
use tradr_app::paths::{app_data_dir, device_keys_dir};

fn print_usage() {
    eprintln!("usage: tradr-cli <command>\n\ncommands:\n  device    Report this device's identity");
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

fn main() {
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
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }
}
