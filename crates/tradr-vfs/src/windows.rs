#![cfg(windows)]

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::RwLock;

use tradr_core::{
    BoxFuture, DirEntry, EntryKind, Metadata, ReadAt, RelPath, RootId, UnixTime, Vfs, VfsError,
    WriteAt,
};

use crate::sanitization::{check_deny_list, check_deny_list_write, is_denied};

#[derive(Debug, Clone)]
struct RootEntry {
    canonical_path: PathBuf,
    read_only: bool,
}

fn map_io_err(err: std::io::Error) -> VfsError {
    match err.kind() {
        std::io::ErrorKind::NotFound => VfsError::NotFound,
        std::io::ErrorKind::PermissionDenied => VfsError::Io(std::io::ErrorKind::PermissionDenied),
        std::io::ErrorKind::AlreadyExists => VfsError::Io(std::io::ErrorKind::AlreadyExists),
        _ => VfsError::Io(err.kind()),
    }
}

fn check_stat_kind(meta: &std::fs::Metadata) -> Result<EntryKind, VfsError> {
    if meta.file_type().is_symlink() {
        return Err(VfsError::UnsupportedEntry);
    }
    if meta.is_dir() {
        Ok(EntryKind::Directory)
    } else if meta.is_file() {
        Ok(EntryKind::File)
    } else {
        Err(VfsError::UnsupportedEntry)
    }
}

fn resolve_path(root_entry: &RootEntry, at: &RelPath) -> Result<PathBuf, VfsError> {
    let mut current_path = root_entry.canonical_path.clone();

    for comp in at.components() {
        current_path.push(comp);

        let meta = std::fs::symlink_metadata(&current_path).map_err(map_io_err)?;
        if meta.file_type().is_symlink() {
            return Err(VfsError::UnsupportedEntry);
        }
    }

    Ok(current_path)
}

fn open_read_sync(root: &RootEntry, at: &RelPath) -> Result<File, VfsError> {
    check_deny_list(at)?;
    if at.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }
    let path = resolve_path(root, at)?;
    let meta = std::fs::symlink_metadata(&path).map_err(map_io_err)?;
    let kind = check_stat_kind(&meta)?;
    if kind != EntryKind::File {
        return Err(VfsError::WrongKind);
    }
    OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(map_io_err)
}

fn open_write_sync(root: &RootEntry, at: &RelPath) -> Result<File, VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(at)?;
    if at.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }

    let mut parent_path = root.canonical_path.clone();
    let components: Vec<&str> = at.components().collect();
    if components.is_empty() {
        return Err(VfsError::WrongKind);
    }
    let (target, parents) = components.split_last().unwrap();

    for comp in parents {
        parent_path.push(comp);
        let meta = std::fs::symlink_metadata(&parent_path).map_err(map_io_err)?;
        if meta.file_type().is_symlink() {
            return Err(VfsError::UnsupportedEntry);
        }
    }

    parent_path.push(target);
    let path = parent_path;

    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        let kind = check_stat_kind(&meta)?;
        if kind != EntryKind::File {
            return Err(VfsError::WrongKind);
        }
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(map_io_err)
}

fn stat_sync(root: &RootEntry, at: &RelPath) -> Result<Metadata, VfsError> {
    check_deny_list(at)?;
    let path = resolve_path(root, at)?;
    let meta = std::fs::symlink_metadata(&path).map_err(map_io_err)?;
    let kind = check_stat_kind(&meta)?;
    let size_bytes = if kind == EntryKind::Directory {
        0
    } else {
        meta.len()
    };
    let modified_time = meta
        .modified()
        .map_err(map_io_err)?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(Metadata {
        kind,
        size_bytes,
        modified: UnixTime::from_secs(modified_time as i64),
    })
}

fn create_dir_sync(root: &RootEntry, at: &RelPath) -> Result<(), VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(at)?;
    if at.as_str().is_empty() {
        return Ok(());
    }

    let mut current_path = root.canonical_path.clone();
    for comp in at.components() {
        current_path.push(comp);

        match std::fs::symlink_metadata(&current_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(VfsError::UnsupportedEntry);
                }
                if !meta.is_dir() {
                    return Err(VfsError::WrongKind);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&current_path).map_err(map_io_err)?;
            }
            Err(e) => return Err(map_io_err(e)),
        }
    }

    Ok(())
}

fn remove_sync(root: &RootEntry, at: &RelPath) -> Result<(), VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(at)?;
    if at.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }
    let path = resolve_path(root, at)?;
    let meta = std::fs::symlink_metadata(&path).map_err(map_io_err)?;
    let kind = check_stat_kind(&meta)?;

    match kind {
        EntryKind::Directory => {
            std::fs::remove_dir(&path).map_err(map_io_err)?;
        }
        EntryKind::File => {
            std::fs::remove_file(&path).map_err(map_io_err)?;
        }
    }
    Ok(())
}

fn rename_sync(root: &RootEntry, from: &RelPath, to: &RelPath) -> Result<(), VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(from)?;
    check_deny_list(to)?;
    if from.as_str().is_empty() || to.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }

    let from_path = resolve_path(root, from)?;

    let to_components: Vec<&str> = to.components().collect();
    let (to_target, to_parents) = to_components.split_last().unwrap();

    if !to_parents.is_empty() {
        let to_parent_rel = to_parents.join("/");
        if let Ok(rel) = RelPath::new(&to_parent_rel) {
            create_dir_sync(root, &rel)?;
        }
    }

    let mut to_parent_path = root.canonical_path.clone();
    for comp in to_parents {
        to_parent_path.push(comp);
        let meta = std::fs::symlink_metadata(&to_parent_path).map_err(map_io_err)?;
        if meta.file_type().is_symlink() {
            return Err(VfsError::UnsupportedEntry);
        }
    }
    let to_path = to_parent_path.join(to_target);

    if let Ok(meta) = std::fs::symlink_metadata(&to_path) {
        check_stat_kind(&meta)?;
    }

    std::fs::rename(&from_path, &to_path).map_err(map_io_err)?;
    Ok(())
}

fn list_sync(root: &RootEntry, at: &RelPath) -> Result<Vec<DirEntry>, VfsError> {
    check_deny_list(at)?;
    let path = resolve_path(root, at)?;
    let meta = std::fs::symlink_metadata(&path).map_err(map_io_err)?;
    let kind = check_stat_kind(&meta)?;
    if kind != EntryKind::Directory {
        return Err(VfsError::WrongKind);
    }

    let mut entries = Vec::new();
    let parent_components: Vec<&str> = at.components().collect();

    let read_dir = std::fs::read_dir(&path).map_err(map_io_err)?;
    for entry_res in read_dir {
        let entry = entry_res.map_err(map_io_err)?;
        let file_name = entry.file_name();
        let name_str = match file_name.to_str() {
            Some(s) => s.to_string(),
            None => return Err(VfsError::Io(std::io::ErrorKind::InvalidData)),
        };

        let mut full_components = parent_components.clone();
        full_components.push(&name_str);
        if is_denied(&full_components) {
            continue;
        }

        let entry_meta = match std::fs::symlink_metadata(entry.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let entry_kind = match check_stat_kind(&entry_meta) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let size_bytes = if entry_kind == EntryKind::Directory {
            0
        } else {
            entry_meta.len()
        };

        let modified_time = entry_meta
            .modified()
            .map_err(map_io_err)?
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        entries.push(DirEntry {
            name: name_str,
            kind: entry_kind,
            size_bytes,
            modified: UnixTime::from_secs(modified_time as i64),
        });
    }

    Ok(entries)
}

pub struct WindowsReadHandle {
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl WindowsReadHandle {
    pub fn new(file: tokio::fs::File) -> Self {
        Self {
            file: tokio::sync::Mutex::new(file),
        }
    }
}

impl ReadAt for WindowsReadHandle {
    fn read_at<'a>(
        &'a self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, VfsError>> {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            let mut file = self.file.lock().await;
            file.seek(SeekFrom::Start(offset))
                .await
                .map_err(map_io_err)?;
            let n = file.read(buf).await.map_err(map_io_err)?;
            Ok(n)
        })
    }
}

pub struct WindowsWriteHandle {
    file: tokio::fs::File,
}

impl WindowsWriteHandle {
    pub fn new(file: tokio::fs::File) -> Self {
        Self { file }
    }
}

impl WriteAt for WindowsWriteHandle {
    fn write_at<'a>(
        &'a mut self,
        offset: u64,
        buf: &'a [u8],
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            use tokio::io::{AsyncSeekExt, AsyncWriteExt};
            self.file
                .seek(SeekFrom::Start(offset))
                .await
                .map_err(map_io_err)?;
            self.file.write_all(buf).await.map_err(map_io_err)?;
            Ok(())
        })
    }

    fn sync<'a>(&'a mut self) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            self.file.sync_all().await.map_err(map_io_err)?;
            Ok(())
        })
    }
}

#[derive(Debug, Default)]
pub struct WindowsVfs {
    roots: RwLock<HashMap<u64, RootEntry>>,
}

impl WindowsVfs {
    pub fn new() -> Self {
        Self {
            roots: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_root(
        &self,
        root: RootId,
        path: PathBuf,
        read_only: bool,
    ) -> Result<(), VfsError> {
        let canonical_path = path.canonicalize().map_err(map_io_err)?;
        let mut roots = self
            .roots
            .write()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        roots.insert(
            root.value(),
            RootEntry {
                canonical_path,
                read_only,
            },
        );
        Ok(())
    }

    fn get_root(&self, root: RootId) -> Result<RootEntry, VfsError> {
        let roots = self
            .roots
            .read()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        roots.get(&root.value()).cloned().ok_or(VfsError::NotFound)
    }
}

impl Vfs for WindowsVfs {
    fn list<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || list_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn stat<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || stat_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn open_read<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            let std_file = tokio::task::spawn_blocking(move || open_read_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))??;
            let tokio_file = tokio::fs::File::from_std(std_file);
            Ok(Box::new(WindowsReadHandle::new(tokio_file)) as Box<dyn ReadAt>)
        })
    }

    fn create_dir<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || create_dir_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn open_write<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            let std_file = tokio::task::spawn_blocking(move || open_write_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))??;
            let tokio_file = tokio::fs::File::from_std(std_file);
            Ok(Box::new(WindowsWriteHandle::new(tokio_file)) as Box<dyn WriteAt>)
        })
    }

    fn rename<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        let from = from.clone();
        let to = to.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || rename_sync(&root_entry, &from, &to))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || remove_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }
}
