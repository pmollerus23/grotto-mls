//! Private local files, created securely before SQLite opens them.

use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

pub fn ensure_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    check_ancestors(parent)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    check_ancestors(parent)?;
    let meta = fs::symlink_metadata(parent)?;
    // SAFETY: geteuid has no arguments and cannot invalidate Rust memory.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "database directory must be owned by this user with mode 0700",
        ));
    }
    Ok(())
}

pub fn open_locked(path: &Path) -> io::Result<File> {
    ensure_parent(path)?;
    check_sidecars(path)?;
    // SAFETY: geteuid takes no arguments and cannot affect Rust memory.
    let uid = unsafe { libc::geteuid() };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "database must be a regular owner-only file",
        ));
    }
    file.try_lock().map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "client database is already in use",
        )
    })?;
    Ok(file)
}

fn check_ancestors(path: &Path) -> io::Result<()> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    for ancestor in absolute.ancestors() {
        let meta = match fs::symlink_metadata(ancestor) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let sticky = meta.mode() & 0o1000 != 0;
        if !meta.is_dir() || (meta.mode() & 0o022 != 0 && !sticky) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe directory ancestor",
            ));
        }
    }
    Ok(())
}

fn check_sidecars(path: &Path) -> io::Result<()> {
    // SAFETY: geteuid takes no arguments and cannot affect Rust memory.
    let uid = unsafe { libc::geteuid() };
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match fs::symlink_metadata(Path::new(&name)) {
            Ok(meta) if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe database sidecar",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn rejects_unsafe_files_symlinks_and_simultaneous_clients() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/client.db");
        let first = open_locked(&path).unwrap();
        assert_eq!(first.metadata().unwrap().mode() & 0o777, 0o600);
        assert!(open_locked(&path).is_err());
        drop(first);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(open_locked(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = path.with_file_name("link.db");
        symlink(&path, &link).unwrap();
        assert!(open_locked(&link).is_err());
        drop(open_locked(&path).unwrap());
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open_locked(&path).is_err());
    }
}
