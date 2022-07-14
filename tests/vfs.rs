//! Add logic for implementing custom virtual filesystems.

#[cfg(feature = "vfs")]
#[cfg(test)]
mod vfs_test {
    use rusqlite::{
        vfs::{register, Filesystem, LockState, OpenOptions, Resource},
        OpenFlags,
    };
    use tempfile::{tempdir, TempDir};

    use std::{
        borrow::Cow,
        ffi::OsStr,
        fs::File,
        io::{BufReader, Read, Seek, Write},
        os::linux::fs::MetadataExt,
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    struct OsFs {
        tempdir: TempDir,
    }

    impl OsFs {
        pub fn new() -> std::io::Result<Arc<Self>> {
            Ok(Arc::new(OsFs {
                tempdir: tempdir()?,
            }))
        }
    }

    struct OsHandle {
        flags: std::fs::OpenOptions,
        path: String,
        lock: LockState,
        delete_on_close: bool,
    }

    impl OsHandle {
        fn file(&self) -> std::io::Result<File> {
            self.flags.open(&self.path)
        }
    }

    impl Resource for OsHandle {
        fn read_bytes(&mut self, mut buffer: &mut [u8], offset: usize) -> std::io::Result<()> {
            println!("[[test]] reading bytes.");
            let file = self.file()?;
            let mut reader = BufReader::new(file.try_clone()?);

            println!(
                "[[test]] at position on open: {:?}",
                reader.stream_position()
            );

            reader.seek_relative(offset as i64)?;
            println!(
                "[[test]] at position after seek: {:?}",
                reader.stream_position()
            );

            file.sync_all()?;
            println!(
                "[[test]] at position after sync: {:?}",
                reader.stream_position()
            );

            reader.read_exact(&mut buffer)?;

            println!(
                "[[test]] at position after 'read': {:?}",
                reader.stream_position()
            );
            println!("[[test]] got {} bytes as {:?}", buffer.len(), buffer);

            file.sync_all()
        }

        fn write_bytes(&mut self, buffer: &[u8], offset: usize) -> std::io::Result<()> {
            println!("[[test]] writing bytes.");
            let mut file = self.file()?;
            let new_pos = file.seek(std::io::SeekFrom::Start(offset as u64))?;
            file.write_all(buffer)
        }

        fn file_size(&self) -> std::io::Result<usize> {
            println!("[[test]] file size.");
            let file = self.file()?;
            file.metadata().map(|m| m.st_size() as usize)
        }

        fn has_moved(&self) -> std::io::Result<bool> {
            println!("[[test]] has moved.");
            std::fs::metadata(&self.path).map(|_| false).or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(true)
                } else {
                    Err(e)
                }
            })
        }

        fn lock_state(&self) -> std::io::Result<LockState> {
            Ok(self.lock)
        }

        fn set_lock_state(&mut self, new_lock_state: LockState) -> std::io::Result<()> {
            self.lock = new_lock_state;
            Ok(())
        }

        fn close(&mut self) -> std::io::Result<()> {
            println!("[[test]] closed.");
            Ok(())
        }
    }

    impl Filesystem for OsFs {
        type Handle = OsHandle;

        fn random_bytes(&self, _buffer: &mut [i8]) {}

        fn sleep(&self, duration: Duration) -> Duration {
            std::thread::sleep(duration);
            duration
        }

        fn open(
            &self,
            path: String,
            sql_flags: OpenOptions,
        ) -> Result<Self::Handle, std::io::Error> {
            Ok(Self::Handle {
                flags: sql_flags.access.into(),
                path,
                lock: LockState::default(),
                delete_on_close: sql_flags.delete_on_close,
            })
        }

        fn temporary_filename(&self) -> std::io::Result<String> {
            let temp_file = tempfile::Builder::new()
                .prefix("rusqlite-vfs-osfs")
                .rand_bytes(8)
                .tempfile()?;

            let temp_file_name = temp_file.path().file_name();

            temp_file_name
                .and_then(OsStr::to_str)
                .map(|s| s.to_string())
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "failed to generate a new temporary file at {:?}",
                        temp_file_name
                    ),
                ))
        }

        fn full_pathname<'a>(&self, pathname: &'a str) -> Result<Cow<'a, str>, std::io::Error> {
            Ok(Cow::Owned(
                normalize_path(Path::new(pathname))
                    .to_string_lossy()
                    .to_string(),
            ))
        }

        fn delete(&self, path: String) -> std::io::Result<()> {
            std::fs::remove_file(path)
        }

        fn exists(&self, path: &str) -> std::io::Result<bool> {
            std::fs::metadata(path).map(|_| true).or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(false)
                } else {
                    Err(e)
                }
            })
        }

        fn access(&self, path: &str, level: rusqlite::vfs::FileAccess) -> std::io::Result<bool> {
            match level {
                rusqlite::vfs::FileAccess::Readonly => {
                    std::fs::metadata(path).map(|m| m.permissions().readonly())
                }
                rusqlite::vfs::FileAccess::Writable | rusqlite::vfs::FileAccess::ReadWrite => {
                    std::fs::metadata(path).map(|m| !m.permissions().readonly())
                }
            }
        }

        fn sector_size() -> usize {
            16
        }
    }

    // Source: https://github.com/rust-lang/cargo/blob/7a3b56b4860c0e58dab815549a93198a1c335b64/crates/cargo-util/src/paths.rs#L81
    fn normalize_path(path: &Path) -> PathBuf {
        use std::path::Component;

        let mut components = path.components().peekable();
        let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
            components.next();
            PathBuf::from(c.as_os_str())
        } else {
            PathBuf::new()
        };

        for component in components {
            match component {
                Component::Prefix(..) => unreachable!(),
                Component::RootDir => {
                    ret.push(component.as_os_str());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    ret.pop();
                }
                Component::Normal(c) => {
                    ret.push(c);
                }
            }
        }
        ret
    }

    #[test]
    fn registers() {
        let register_result = register("test-vfs", OsFs::new().expect("failed to expect"), false);
        assert!(register_result.is_ok());
    }

    #[test]
    fn generates_schema_on_disk() {
        let mock_fs = OsFs::new().expect("failed to expect");

        let register_result = register("test-vfs", mock_fs, false);
        assert_eq!(
            register_result.as_ref().err(),
            None,
            "registered vfs safely"
        );

        let conn_result = rusqlite::Connection::open_with_flags_and_vfs(
            "file:test.sqlite?wal=off",
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "test-vfs",
        );

        assert_eq!(conn_result.as_ref().err(), None, "connection was opened");

        let conn = conn_result.unwrap();

        assert_eq!(
            conn.execute(
                r#"
                    CREATE TABLE IF NOT EXISTS person (
                        id      INTEGER PRIMARY KEY,
                        name    TEXT NOT NULL,
                        data    BLOB
                    );
                "#,
                []
            )
            .err(),
            // .as_ref()
            // .and_then(|e| e.sqlite_error())
            // .map(|e| unsafe { CStr::from_ptr(sqlite3_errstr(e.extended_code)) }),
            None,
            "creates a table"
        );

        assert_eq!(
            conn.execute(
                "INSERT INTO person (name, data) VALUES (?1, ?2)",
                rusqlite::params!["Frederick Douglass".to_string(), Some(Vec::default())],
            )
            .err(),
            None,
            "inserting records"
        );

        let stmt_result = conn.prepare("SELECT id, name, data FROM person");
        assert_eq!(stmt_result.as_ref().err(), None, "can build statements");
        let mut stmt = stmt_result.unwrap();

        let person_iter_result = stmt.query_map(rusqlite::NO_PARAMS, |row| row.get::<usize, u8>(0));
        assert_eq!(person_iter_result.as_ref().err(), None, "can get rows out");
        let person_iter = person_iter_result.unwrap();

        for person in person_iter {
            println!("Found person {:?}", person.unwrap());
        }

        assert_eq!(
            conn.execute(
                "ALTER TABLE person ADD COLUMN age INTEGER NOT NULL DEFAULT 18;",
                rusqlite::params![],
            )
            .err(),
            None,
            "inserting records"
        );
    }

    #[test]
    fn generates_schema_with_in_memory() {
        let mock_fs = OsFs::new().expect("failed to expect");

        let register_result = register("test-vfs", mock_fs, false);
        assert_eq!(
            register_result.as_ref().err(),
            None,
            "registered vfs safely"
        );

        let conn_result = rusqlite::Connection::open_with_flags_and_vfs(
            ":memory:",
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "test-vfs",
        );

        assert_eq!(conn_result.as_ref().err(), None, "connection was opened");

        let conn = conn_result.unwrap();

        assert_eq!(
            conn.execute(
                r#"
                    CREATE TABLE IF NOT EXISTS person (
                        id      INTEGER PRIMARY KEY,
                        name    TEXT NOT NULL,
                        data    BLOB
                    );
                "#,
                []
            )
            .err(),
            // .as_ref()
            // .and_then(|e| e.sqlite_error())
            // .map(|e| unsafe { CStr::from_ptr(sqlite3_errstr(e.extended_code)) }),
            None,
            "creates a table"
        );

        assert_eq!(
            conn.execute(
                "INSERT INTO person (name, data) VALUES (?1, ?2)",
                rusqlite::params!["Frederick Douglass".to_string(), Some(Vec::default())],
            )
            .err(),
            None,
            "inserting records"
        );

        let stmt_result = conn.prepare("SELECT id, name, data FROM person");
        assert_eq!(stmt_result.as_ref().err(), None, "can build statements");
        let mut stmt = stmt_result.unwrap();

        let person_iter_result = stmt.query_map(rusqlite::NO_PARAMS, |row| row.get::<usize, u8>(0));
        assert_eq!(person_iter_result.as_ref().err(), None, "can get rows out");
        let person_iter = person_iter_result.unwrap();

        for person in person_iter {
            println!("Found person {:?}", person.unwrap());
        }

        assert_eq!(
            conn.execute(
                "ALTER TABLE person ADD COLUMN age INTEGER NOT NULL DEFAULT 18;",
                rusqlite::params![],
            )
            .err(),
            None,
            "inserting records"
        );
    }
}
