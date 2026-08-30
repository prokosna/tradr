//! Supervisor-authored tests for docs/06's default deny list.
//! Critical Module: boundary enforcement in tradr-vfs.
//! See docs/06-shares-and-browsing.md, "The default deny list" and
//! "How a pattern matches" (DCR-056), and CLAUDE.md section 6.

use std::path::Path;
use tradr_core::{RelPath, RootId, Vfs, VfsError};
use tradr_vfs::PosixVfs;

fn rooted(dir: &Path) -> (PosixVfs, RootId) {
    let vfs = PosixVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, dir.to_path_buf(), false)
        .expect("register root");
    (vfs, root)
}

fn rel(s: &str) -> RelPath {
    RelPath::new(s).unwrap_or_else(|e| panic!("{s} must be a valid RelPath: {e}"))
}

// Every literal and glob docs/06 lists, each written as a path a peer
// could ask for. A miss here is a file a peer reads that the design
// says it may not.
const DENIED: &[&str] = &[
    ".ssh/config",
    ".ssh/id_rsa",
    "projects/.ssh/known_hosts",
    ".gnupg/secring.gpg",
    ".aws/credentials",
    ".kube/config",
    ".config/gcloud/credentials.db",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "server.pem",
    "certs/chain.pem",
    "server.key",
    "bundle.p12",
    "bundle.pfx",
    "release.keystore",
    "release.jks",
    ".env",
    ".env.production",
    ".env.local",
    "id_rsa",
    "id_rsa.pub",
    "id_rsa_backup",
    "id_ed25519",
    "id_ed25519_work",
    "id_ecdsa",
    "id_ecdsa.pub",
];

// docs/06 says these stay reachable. `.git`, `node_modules`, `target`
// and `__pycache__` are collapsed in listings and remain accessible, and
// `.bash_history` appears in no document at all.
const ALLOWED: &[&str] = &[
    ".git/config",
    ".git/HEAD",
    ".bash_history",
    "node_modules/left-pad/index.js",
    "target/debug/build.log",
    "__pycache__/module.pyc",
    ".config/settings.toml",
    ".config/other/file.txt",
    ".docker/daemon.json",
    "pem",
    "key",
    "notes.pem.txt",
    "my.env.txt",
    "keystore",
    "readme.md",
    "envelope.txt",
];

async fn deny_verdict(vfs: &PosixVfs, root: RootId, path: &str) -> Result<(), VfsError> {
    match vfs.open_read(root, &rel(path)).await {
        Err(VfsError::DenyListed) => Err(VfsError::DenyListed),
        _ => Ok(()),
    }
}

#[tokio::test]
async fn every_documented_pattern_is_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path());

    for path in DENIED {
        assert_eq!(
            deny_verdict(&vfs, root, path).await,
            Err(VfsError::DenyListed),
            "docs/06 denies {path}, and the deny list let it through"
        );
    }
}

#[tokio::test]
async fn matching_is_case_insensitive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path());

    for path in [
        "ID_RSA",
        "Id_Rsa.pub",
        ".SSH/config",
        ".Env.Production",
        "SERVER.PEM",
        "Release.JKS",
        ".NetRC",
    ] {
        assert_eq!(
            deny_verdict(&vfs, root, path).await,
            Err(VfsError::DenyListed),
            "{path} differs from a denied name only in case"
        );
    }
}

#[tokio::test]
async fn what_the_design_serves_is_not_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path());

    for path in ALLOWED {
        assert_eq!(
            deny_verdict(&vfs, root, path).await,
            Ok(()),
            "docs/06 keeps {path} accessible, and the deny list refused it"
        );
    }
}

#[tokio::test]
async fn a_star_does_not_cross_a_separator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path());

    assert_eq!(
        deny_verdict(&vfs, root, "pem/notes.txt").await,
        Ok(()),
        "a directory named pem is not a file matching *.pem"
    );
    assert_eq!(
        deny_verdict(&vfs, root, "id_rsa_dir/notes.txt").await,
        Err(VfsError::DenyListed),
        "id_rsa* matches a component whether it names a file or a directory"
    );
}

#[tokio::test]
async fn a_multi_component_pattern_matches_only_a_consecutive_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path());

    assert_eq!(
        deny_verdict(&vfs, root, ".config/gcloud/x").await,
        Err(VfsError::DenyListed)
    );
    assert_eq!(
        deny_verdict(&vfs, root, "nested/.config/gcloud/x").await,
        Err(VfsError::DenyListed),
        "a run matches at any depth, not only at the Share Root"
    );
    assert_eq!(
        deny_verdict(&vfs, root, ".config/aws/gcloud/x").await,
        Ok(()),
        "the components must be consecutive"
    );
    assert_eq!(
        deny_verdict(&vfs, root, "gcloud/credentials.db").await,
        Ok(()),
        "gcloud alone is not a deny entry"
    );
}

#[tokio::test]
async fn denial_covers_every_operation_not_only_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path());
    let secret = rel(".ssh/id_rsa");
    let ordinary = rel("notes.txt");

    assert_eq!(
        vfs.open_write(root, &secret).await.err(),
        Some(VfsError::DenyListed)
    );
    assert_eq!(
        vfs.stat(root, &secret).await.err(),
        Some(VfsError::DenyListed)
    );
    assert_eq!(
        vfs.create_dir(root, &secret).await.err(),
        Some(VfsError::DenyListed)
    );
    assert_eq!(
        vfs.remove(root, &secret).await.err(),
        Some(VfsError::DenyListed)
    );
    assert_eq!(
        vfs.list(root, &rel(".ssh")).await.err(),
        Some(VfsError::DenyListed)
    );
    assert_eq!(
        vfs.rename(root, &secret, &ordinary).await.err(),
        Some(VfsError::DenyListed),
        "a rename must not be a way to read a denied file under another name"
    );
    assert_eq!(
        vfs.rename(root, &ordinary, &secret).await.err(),
        Some(VfsError::DenyListed),
        "nor a way to write one"
    );
}

#[tokio::test]
async fn a_listing_omits_denied_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".netrc"), b"secret").expect("write");
    std::fs::write(dir.path().join("id_rsa"), b"secret").expect("write");
    std::fs::write(dir.path().join("server.pem"), b"secret").expect("write");
    std::fs::write(dir.path().join(".bash_history"), b"ordinary").expect("write");
    std::fs::write(dir.path().join("readme.md"), b"ordinary").expect("write");
    std::fs::create_dir(dir.path().join(".ssh")).expect("mkdir");
    std::fs::create_dir(dir.path().join(".git")).expect("mkdir");
    let (vfs, root) = rooted(dir.path());

    let names: Vec<String> = vfs
        .list(root, &RelPath::root())
        .await
        .expect("listing the Share Root")
        .into_iter()
        .map(|entry| entry.name)
        .collect();

    for hidden in [".netrc", "id_rsa", "server.pem", ".ssh"] {
        assert!(
            !names.iter().any(|n| n == hidden),
            "docs/06: a denied entry is neither listed nor accessible, and {hidden} was listed"
        );
    }
    for shown in [".bash_history", "readme.md", ".git"] {
        assert!(
            names.iter().any(|n| n == shown),
            "{shown} is accessible under docs/06 and must appear in a listing"
        );
    }
}
