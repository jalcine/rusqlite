//! Add logic for implementing custom virtual filesystems.

#[cfg(feature = "vfs")]
#[cfg(test)]
mod vfs_test {
    use rusqlite::{
        vfs::{register, Filesystem, LockState, OpenOptions, Resource},
        OpenFlags,
    };

    use std::{
        borrow::Cow,
        io::{Read, Write},
        os::linux::fs::MetadataExt,
        path::{Path, PathBuf},
        time::Duration,
    };

    struct OsFs {}
    struct OsHandle {
        file: std::fs::File,
        lock: LockState,
    }

    impl Resource for OsHandle {
        fn read_bytes(&mut self, buffer: &mut [u8], offset: usize) -> std::io::Result<()> {
            use std::io::{Seek, SeekFrom};
            self.file.seek(SeekFrom::Start(offset as u64))?;
            self.file.read(buffer).and(Ok(()))
        }

        fn write_bytes(&mut self, buffer: &[u8], offset: usize) -> std::io::Result<()> {
            use std::io::{Seek, SeekFrom};
            self.file.seek(SeekFrom::Start(offset as u64))?;
            self.file.write_all(buffer)
        }

        fn file_size(&self) -> std::io::Result<usize> {
            self.file.metadata().map(|m| m.st_size() as usize)
        }

        fn has_moved(&self) -> std::io::Result<bool> {
            Ok(false)
        }

        fn lock_state(&self) -> std::io::Result<LockState> {
            Ok(self.lock)
        }

        fn set_lock_state(&mut self, new_lock_state: LockState) -> std::io::Result<()> {
            self.lock = new_lock_state;
            Ok(())
        }

        fn close(&mut self) -> std::io::Result<()> {
            self.file.sync_all()
        }
    }

    impl Filesystem for OsFs {
        type Handle = OsHandle;

        fn random_bytes(&self, _buffer: &mut [i8]) {}

        fn sleep(&self, duration: Duration) -> Duration {
            std::thread::sleep(duration);
            duration
        }

        fn open(&self, path: String, flags: OpenOptions) -> Result<Self::Handle, std::io::Error> {
            let flags: std::fs::OpenOptions = flags.access.into();
            let file = flags.open(path)?;

            Ok(Self::Handle {
                file,
                lock: LockState::default(),
            })
        }

        fn temporary_name(&self) -> String {
            todo!()
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
        let register_result = register("test-vfs", OsFs {}, false);
        assert!(register_result.is_ok());
    }

    #[test]
    fn generates_schema() {
        let mock_fs = OsFs {};

        let register_result = register("test-vfs", mock_fs, false);
        assert_eq!(
            register_result.as_ref().err(),
            None,
            "registered vfs safely"
        );

        let conn_result = rusqlite::Connection::open_with_flags_and_vfs(
            "file:./test.sqlite",
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "test-vfs",
        );

        assert_eq!(conn_result.as_ref().err(), None, "connection was opened");

        let conn = conn_result.unwrap();

        assert_eq!(
            conn.execute(
                r#"
                    CREATE TABLE person (
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
            "no errors when inserting records"
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
    }
}
