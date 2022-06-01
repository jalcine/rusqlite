use libsqlite3_sys as ffi;
use std::{ffi::CStr, marker::PhantomData, os::raw, slice};

use crate::{str_to_cstring, Error};

///! Implement virtual file systems.
///!
///! (See [SQLite doc](http://sqlite.org/vfs.html))

// FIXME: Change this value based on flags;
static IMPL_VERSION: u8 = 3;

/// Logic around defining a virtual table.
pub trait Vfs<'vfs> {
    /// Depending on the feature flag used, this returns a value accordingly.
    fn version() -> raw::c_int {
        IMPL_VERSION as raw::c_int
    }

    /// Reports the max length of a file name on this system.
    fn max_file_path_name_length() -> raw::c_int {
        raw::c_int::MAX
    }

    /// Reports the name of the virtual file system.
    fn name() -> *const raw::c_char;

    /// Opens up a file.
    fn open();

    /// .
    fn delete();

    /// .
    fn access();

    /// .
    fn full_path_name();

    /// .
    fn dl_open();

    /// .
    fn dl_error();

    /// .
    fn dl_sym();

    /// .
    fn dl_close();

    /// .
    fn randomness();

    /// .
    fn sleep();

    /// .
    fn current_time();

    /// .
    fn get_last_error();

    // v2 of vfs

    /// .
    fn current_time_64();
}

/// Module representing a virtual file system.
#[repr(transparent)]
pub struct Module<'vfs, T: Vfs<'vfs>> {
    base: ffi::sqlite3_vfs,
    phantom: PhantomData<&'vfs T>,
}

impl<'vfs, T: Vfs<'vfs>> Module<'vfs, T> {
    fn register() {}
    fn unregister() {}
}

impl<'vfs, T: Vfs<'vfs>> Drop for Module<'vfs, T> {
    fn drop(&mut self) {
        todo!()
    }
}

/// `feature = "vfs"`
pub struct VfsConnection(*mut ffi::sqlite3);

unsafe impl<'vfs, T: Vfs<'vfs>> Send for Module<'vfs, T> {}
unsafe impl<'vfs, T: Vfs<'vfs>> Sync for Module<'vfs, T> {}

unsafe extern "C" fn rust_connect<'vfs, T>(
    db: *mut ffi::sqlite3,
    aux: *mut raw::c_void,
    argc: raw::c_int,
    argv: *const *const raw::c_char,
    pp_vtab: *mut *mut ffi::sqlite3_vfs,
    err_msg: *mut *mut raw::c_char,
) -> raw::c_int
where
    T: Vfs<'vfs>,
{
    let mut conn = VfsConnection(db);
    let args = slice::from_raw_parts(argv, argc as usize);
    let vec = args
        .iter()
        .map(|&cs| CStr::from_ptr(cs).to_bytes()) // FIXME .to_str() -> Result<&str, Utf8Error>
        .collect::<Vec<_>>();

    raw::c_int::MAX
}

unsafe extern "C" fn rust_vfs_name<'vfs, T>() -> *const raw::c_char {
    panic!("at the disco")
}

unsafe extern "C" fn rust_path_name<'vfs, T>() -> raw::c_int {
    panic!("at the disco")
}

unsafe extern "C" fn rust_open<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const raw::c_char,
    file: *mut ffi::sqlite3_file,
    flags: raw::c_int,
    resulting_flags: *mut raw::c_int,
) -> raw::c_int {
    panic!("at the disco")
}

unsafe extern "C" fn rust_delete<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const raw::c_char,
    sync_directory: raw::c_int,
) -> raw::c_int {
    panic!("at the disco")
}

unsafe extern "C" fn rust_access<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const raw::c_char,
    flags: raw::c_int,
    resulting_flags: *mut raw::c_int,
) -> raw::c_int {
    panic!("at the disco")
}

unsafe extern "C" fn rust_full_path_name<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const raw::c_char,
    name_size: raw::c_int,
    resulting_file_path: *mut raw::c_char,
) -> raw::c_int {
    panic!("at the disco")
}

unsafe extern "C" fn rust_randomness<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    bytes_count: raw::c_int,
    resulting_bytes: *mut raw::c_char,
) -> raw::c_int {
    panic!("at the disco")
}

unsafe extern "C" fn rust_sleep<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    microseconds: raw::c_int,
) -> raw::c_int {
    panic!("at the disco")
}
unsafe extern "C" fn rust_current_time<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    resulting_time: *mut raw::c_double,
) -> raw::c_int {
    panic!("at the disco")
}
unsafe extern "C" fn rust_get_last_error<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    error_code: raw::c_int,
    error_message: *mut raw::c_char,
) -> raw::c_int {
    panic!("at the disco")
}
unsafe extern "C" fn rust_current_time_64<'vfs, T>(
    vfs: *mut ffi::sqlite3_vfs,
    resulting_time: *mut raw::c_long,
) -> raw::c_int {
    panic!("at the disco")
}
#[cold]
unsafe fn result_error<T>(ctx: *mut ffi::sqlite3_context, result: crate::Result<T>) -> raw::c_int {
    match result {
        Ok(_) => ffi::SQLITE_OK,
        Err(Error::SqliteFailure(err, s)) => {
            match err.extended_code {
                ffi::SQLITE_TOOBIG => {
                    ffi::sqlite3_result_error_toobig(ctx);
                }
                ffi::SQLITE_NOMEM => {
                    ffi::sqlite3_result_error_nomem(ctx);
                }
                code => {
                    ffi::sqlite3_result_error_code(ctx, code);
                    if let Some(Ok(cstr)) = s.map(|s| str_to_cstring(&s)) {
                        ffi::sqlite3_result_error(ctx, cstr.as_ptr(), -1);
                    }
                }
            };
            err.extended_code
        }
        Err(err) => {
            ffi::sqlite3_result_error_code(ctx, ffi::SQLITE_ERROR);
            if let Ok(cstr) = str_to_cstring(&err.to_string()) {
                ffi::sqlite3_result_error(ctx, cstr.as_ptr(), -1);
            }
            ffi::SQLITE_ERROR
        }
    }
}

/// Registers a virtual filesystem into SQLite.
///
/// # Safety
/// This function's not safe since it needs to build a SQLite
/// object for virtual systems and in the act of creating, it has
/// to create C-level objects that are `unsafe`.
pub unsafe fn register<'vfs, T: Vfs<'vfs>>(
    instance: T,
    use_as_default: bool,
) -> Result<Module<'vfs, T>, crate::Error> {
    let mut base = ffi::sqlite3_vfs {
        iVersion: T::version(),
        szOsFile: 32,
        mxPathname: rust_path_name::<T>(),
        zName: rust_vfs_name::<T>(),
        pAppData: Box::into_raw(Box::new(instance)).cast::<raw::c_void>(),
        xOpen: Some(rust_open::<T>),
        xDelete: Some(rust_delete::<T>),
        xAccess: Some(rust_access::<T>),
        xFullPathname: Some(rust_full_path_name::<T>),
        xDlOpen: None,
        xDlError: None,
        xDlSym: None,
        xDlClose: None,
        xRandomness: Some(rust_randomness::<T>),
        xSleep: Some(rust_sleep::<T>),
        xCurrentTime: Some(rust_current_time::<T>),
        xGetLastError: Some(rust_get_last_error::<T>),
        xCurrentTimeInt64: Some(rust_current_time_64::<T>),
        xSetSystemCall: None,
        xGetSystemCall: None,
        xNextSystemCall: None,
        pNext: std::ptr::null_mut(),
    };
    let make_default = use_as_default as raw::c_int;
    let result = ffi::sqlite3_vfs_register(&mut base, make_default);

    if result == ffi::SQLITE_OK {
        Ok(Module {
            base,
            phantom: PhantomData::<&T>,
        })
    } else {
        // FIXME: Add custom error here.
        panic!("ffoo")
    }
}

#[cfg(test)]
mod test {
    pub struct TestVfs {}
    impl super::Vfs<'_> for TestVfs {
        fn name() -> *const std::os::raw::c_char {
            todo!()
        }

        fn open() {
            todo!()
        }

        fn delete() {
            todo!()
        }

        fn access() {
            todo!()
        }

        fn full_path_name() {
            todo!()
        }

        fn dl_open() {
            todo!()
        }

        fn dl_error() {
            todo!()
        }

        fn dl_sym() {
            todo!()
        }

        fn dl_close() {
            todo!()
        }

        fn randomness() {
            todo!()
        }

        fn sleep() {
            todo!()
        }

        fn current_time() {
            todo!()
        }

        fn get_last_error() {
            todo!()
        }

        fn current_time_64() {
            todo!()
        }
    }
    #[test]
    fn loads() {
        let a_vfs = TestVfs {};
        unsafe {
            assert_eq!(super::register(a_vfs, false).and(Ok(())), Ok(()));
        }
    }
}
