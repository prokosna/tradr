// Bakes the OAuth client into the build (DCR-030, docs/05-security.md
// "OAuth client configuration"). The environment wins; a gitignored
// `.tradr-deployment.env` at the repository root is the fallback. Android
// never receives the secret: a value absent from the artifact cannot be
// extracted from it.

use std::env;
use std::fs;
use std::path::PathBuf;

const CLIENT_IDS_VAR: &str = "TRADR_OAUTH_CLIENT_IDS";
const CLIENT_SECRET_VAR: &str = "TRADR_OAUTH_CLIENT_SECRET";
const DEPLOYMENT_ENV_FILE: &str = ".tradr-deployment.env";

// `KEY=VALUE` lookup in a `.tradr-deployment.env`-shaped file. Blank lines
// and lines starting with `#` are skipped; a value is everything after the
// first `=`, trimmed of surrounding whitespace only.
fn lookup(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (line_key, value) = trimmed.split_once('=')?;
        if line_key.trim() == key {
            return Some(value.trim().to_string());
        }
    }
    None
}

// The value for `key`: the environment if set and non-empty, else the
// matching line in `.tradr-deployment.env` at the repository root, else
// empty.
fn resolve(key: &str, deployment_env: Option<&str>) -> String {
    if let Ok(value) = env::var(key)
        && !value.is_empty()
    {
        return value;
    }
    deployment_env
        .and_then(|contents| lookup(contents, key))
        .unwrap_or_default()
}

fn main() {
    tauri_build::build();

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("apps/tradr/src-tauri has a repository root three levels up")
        .to_path_buf();
    let deployment_env_path = repo_root.join(DEPLOYMENT_ENV_FILE);
    let deployment_env = fs::read_to_string(&deployment_env_path).ok();

    let client_ids = resolve(CLIENT_IDS_VAR, deployment_env.as_deref());
    let client_secret = resolve(CLIENT_SECRET_VAR, deployment_env.as_deref());

    println!("cargo::rustc-env={CLIENT_IDS_VAR}={client_ids}");

    // No secret in an Android artifact: nothing there uses it, and a value
    // never emitted cannot be extracted from a shipped binary.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "android" {
        println!("cargo::rustc-env={CLIENT_SECRET_VAR}={client_secret}");
    }

    println!("cargo::rerun-if-env-changed={CLIENT_IDS_VAR}");
    println!("cargo::rerun-if-env-changed={CLIENT_SECRET_VAR}");
    println!("cargo::rerun-if-changed={}", deployment_env_path.display());
}
