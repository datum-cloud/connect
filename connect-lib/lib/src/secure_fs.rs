//! Private on-disk storage shared by the daemon and legacy repository.
//!
//! On Windows every object gets a protected DACL granting full control only
//! to the process account, LocalSystem, and the built-in Administrators group.

use std::{fs::File, io, path::Path};

pub const PRIVATE_DIR_MODE: u32 = 0o700;
pub const PRIVATE_FILE_MODE: u32 = 0o600;

pub async fn ensure_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        tokio::fs::create_dir_all(path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
                .await?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || windows::ensure_private_dir(&path))
            .await
            .map_err(|error| io::Error::other(format!("joining private-directory task: {error}")))?
    }
}

pub async fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
                .await?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || windows::protect_and_validate(&path))
            .await
            .map_err(|error| io::Error::other(format!("joining private-ACL task: {error}")))?
    }
}

/// Reject a path unless its Windows DACL is exactly the private daemon policy.
/// Unix callers perform their existing mode/ownership checks at the call site.
pub async fn validate_private_path(path: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
    #[cfg(windows)]
    {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || windows::validate(&path))
            .await
            .map_err(|error| {
                io::Error::other(format!("joining private-ACL validation task: {error}"))
            })?
    }
}

/// Create a new file without a window in which it inherits a permissive ACL.
pub fn create_new_private(path: &Path, read: bool, write: bool) -> io::Result<File> {
    #[cfg(windows)]
    {
        windows::create_new_private(path, read, write)
    }
    #[cfg(not(windows))]
    {
        let mut options = std::fs::OpenOptions::new();
        options.read(read).write(write).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(PRIVATE_FILE_MODE);
        }
        options.open(path)
    }
}

/// Open or create a private lock file, repairing an existing file before use.
pub fn open_private_lock(path: &Path) -> io::Result<File> {
    match create_new_private(path, true, true) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            #[cfg(windows)]
            windows::protect_and_validate(path)?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
            }
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

/// Open or create a private append-only log file.
pub fn open_private_append(path: &Path) -> io::Result<File> {
    match create_new_private(path, false, true) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            #[cfg(windows)]
            windows::protect_and_validate(path)?;
            let file = std::fs::OpenOptions::new().append(true).open(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
            }
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

pub async fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        tokio::fs::rename(source, destination).await
    }
    #[cfg(windows)]
    {
        let source = source.to_owned();
        let destination = destination.to_owned();
        tokio::task::spawn_blocking(move || windows::atomic_replace(&source, &destination))
            .await
            .map_err(|error| io::Error::other(format!("joining atomic-replace task: {error}")))?
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        io,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        path::{Path, PathBuf},
        ptr,
    };
    use windows::{
        Win32::{
            Foundation::{
                CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree,
            },
            Security::{
                ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
                },
                DACL_SECURITY_INFORMATION, GetAclInformation, GetSecurityDescriptorControl,
                GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
                PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
                TOKEN_QUERY, TOKEN_USER, TokenUser,
            },
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
                FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ,
                FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, GetFileAttributesW, GetFileInformationByHandle,
                INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
                MoveFileExW, OPEN_EXISTING,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        },
        core::{PCWSTR, PWSTR},
    };

    struct Local(HLOCAL);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(self.0));
            }
        }
    }
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }
    fn win32(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }

    fn sid_string(sid: PSID) -> io::Result<String> {
        let mut sid_text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid, &mut sid_text) }
            .map_err(|error| io::Error::other(error.to_string()))?;
        let sid_mem = Local(HLOCAL(sid_text.0.cast()));
        let mut length = 0;
        unsafe {
            while *sid_text.0.add(length) != 0 {
                length += 1;
            }
        }
        let result = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text.0, length) })
            .map_err(|_| io::Error::other("account SID was not valid UTF-16"));
        drop(sid_mem);
        result
    }

    fn descriptor_for_sid(sid: &str) -> io::Result<(Local, PSECURITY_DESCRIPTOR)> {
        let dacl = if sid == "S-1-5-18" || sid == "S-1-5-32-544" {
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned()
        } else {
            format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)")
        };
        let sddl = wide(std::ffi::OsStr::new(&dacl));
        let mut raw = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1,
                &mut raw,
                None,
            )
        }
        .map_err(|error| io::Error::other(error.to_string()))?;
        Ok((Local(HLOCAL(raw.0)), raw))
    }

    fn current_sid_string() -> io::Result<String> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|error| io::Error::other(error.to_string()))?;
        let token = Handle(token);
        let mut needed = 0;
        let _ = unsafe {
            windows::Win32::Security::GetTokenInformation(token.0, TokenUser, None, 0, &mut needed)
        };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = vec![0u8; needed as usize];
        unsafe {
            windows::Win32::Security::GetTokenInformation(
                token.0,
                TokenUser,
                Some(bytes.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(|error| io::Error::other(error.to_string()))?;
        let user = unsafe { &*(bytes.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(user.User.Sid)
    }

    fn descriptor() -> io::Result<(Local, PSECURITY_DESCRIPTOR)> {
        descriptor_for_sid(&current_sid_string()?)
    }

    fn descriptor_dacl(sd: PSECURITY_DESCRIPTOR) -> io::Result<*mut ACL> {
        let mut present = windows::core::BOOL(0);
        let mut defaulted = windows::core::BOOL(0);
        let mut acl = ptr::null_mut();
        unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) }
            .map_err(|error| io::Error::other(error.to_string()))?;
        if !present.as_bool() || acl.is_null() {
            return Err(io::Error::other("private security descriptor has no DACL"));
        }
        Ok(acl)
    }

    pub(super) fn protect_and_validate(path: &Path) -> io::Result<()> {
        reject_reparse_path(path)?;
        let name = wide(path.as_os_str());
        let owner = owner_sid(path)?;
        let (_expected_mem, expected_sd) = descriptor_for_sid(&owner)?;
        let expected_acl = descriptor_dacl(expected_sd)?;
        let result = unsafe {
            SetNamedSecurityInfoW(
                PWSTR(name.as_ptr() as *mut _),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(expected_acl),
                None,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(win32(result.0));
        }

        validate(path)
    }

    pub(super) fn validate(path: &Path) -> io::Result<()> {
        reject_reparse_path(path)?;
        let name = wide(path.as_os_str());
        let mut owner = PSID::default();
        let mut actual_acl = ptr::null_mut();
        let mut actual_sd = PSECURITY_DESCRIPTOR::default();
        let result = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut actual_acl),
                None,
                &mut actual_sd,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(win32(result.0));
        }
        let actual_mem = Local(HLOCAL(actual_sd.0));
        let owner = sid_string(owner)?;
        validate_owner(&owner)?;
        let (_expected_mem, expected_sd) = descriptor_for_sid(&owner)?;
        let expected_acl = descriptor_dacl(expected_sd)?;
        let mut control = Default::default();
        let mut revision = 0;
        unsafe { GetSecurityDescriptorControl(actual_sd, &mut control, &mut revision) }
            .map_err(|error| io::Error::other(error.to_string()))?;
        if control & SE_DACL_PROTECTED.0 == 0 {
            return Err(io::Error::other("private DACL inheritance remains enabled"));
        }
        if actual_acl.is_null() {
            return Err(io::Error::other("private path has a NULL DACL"));
        }
        let expected = acl_bytes(expected_acl)?;
        let actual = acl_bytes(actual_acl)?;
        drop(actual_mem);
        if expected != actual {
            return Err(io::Error::other("private DACL validation failed"));
        }
        Ok(())
    }

    fn owner_sid(path: &Path) -> io::Result<String> {
        let name = wide(path.as_os_str());
        let mut owner = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let result = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                None,
                None,
                &mut sd,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(win32(result.0));
        }
        let memory = Local(HLOCAL(sd.0));
        let owner = sid_string(owner)?;
        drop(memory);
        validate_owner(&owner)?;
        Ok(owner)
    }

    fn validate_owner(owner: &str) -> io::Result<()> {
        let current = current_sid_string()?;
        if owner == current || owner == "S-1-5-18" || owner == "S-1-5-32-544" {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private storage must be owned by the current account, SYSTEM, or Administrators",
            ))
        }
    }

    fn acl_bytes(acl: *const ACL) -> io::Result<Vec<u8>> {
        let mut info = ACL_SIZE_INFORMATION::default();
        unsafe {
            GetAclInformation(
                acl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(
            unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), info.AclBytesInUse as usize) }
                .to_vec(),
        )
    }

    pub(super) fn ensure_private_dir(path: &Path) -> io::Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private directory path is not a directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut missing = Vec::<PathBuf>::new();
        let mut cursor = path;
        while !cursor.as_os_str().is_empty() && !cursor.exists() {
            missing.push(cursor.to_owned());
            cursor = cursor.parent().unwrap_or_else(|| Path::new(""));
        }
        if !cursor.as_os_str().is_empty() {
            reject_reparse_path(cursor)?;
        }
        let (sd_mem, sd) = descriptor()?;
        let attrs = windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        for directory in missing.iter().rev() {
            let name = wide(directory.as_os_str());
            if unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attrs)) }.is_err() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS.0 as i32) {
                    return Err(error);
                }
            }
            protect_and_validate(directory)?;
        }
        drop(sd_mem);
        protect_and_validate(path)
    }

    pub(super) fn create_new_private(
        path: &Path,
        read: bool,
        write: bool,
    ) -> io::Result<std::fs::File> {
        let (sd_mem, sd) = descriptor()?;
        let attrs = windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let name = wide(path.as_os_str());
        let mut access = 0;
        if read {
            access |= FILE_GENERIC_READ.0;
        }
        if write {
            access |= FILE_GENERIC_WRITE.0;
        }
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                Some(&attrs),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|_| io::Error::last_os_error())?;
        drop(sd_mem);
        let file = unsafe { std::fs::File::from_raw_handle(handle.0) };
        protect_and_validate(path)?;
        Ok(file)
    }

    pub(super) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
        reject_reparse_path(source)?;
        if destination.exists() {
            reject_reparse_path(destination)?;
        }
        let source_wide = wide(source.as_os_str());
        let destination_wide = wide(destination.as_os_str());
        unsafe {
            MoveFileExW(
                PCWSTR(source_wide.as_ptr()),
                PCWSTR(destination_wide.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| io::Error::last_os_error())?;
        protect_and_validate(destination)
    }

    fn reject_reparse_path(path: &Path) -> io::Result<()> {
        let mut cursor = Some(path);
        while let Some(component) = cursor {
            if component.exists() {
                let name = wide(component.as_os_str());
                let attributes = unsafe { GetFileAttributesW(PCWSTR(name.as_ptr())) };
                if attributes == INVALID_FILE_ATTRIBUTES {
                    return Err(io::Error::last_os_error());
                }
                if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "private storage path must not contain a reparse point",
                    ));
                }
            }
            cursor = component.parent();
        }
        if std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
            let name = wide(path.as_os_str());
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(name.as_ptr()),
                    FILE_READ_ATTRIBUTES.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }
            .map_err(|_| io::Error::last_os_error())?;
            let handle = Handle(handle);
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            unsafe { GetFileInformationByHandle(handle.0, &mut info) }
                .map_err(|error| io::Error::other(error.to_string()))?;
            if info.nNumberOfLinks != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private storage files must not have hard links",
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn set_null_dacl(path: &Path) -> io::Result<()> {
        let name = wide(path.as_os_str());
        let result = unsafe {
            SetNamedSecurityInfoW(
                PWSTR(name.as_ptr() as *mut _),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
            )
        };
        if result == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(win32(result.0))
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[tokio::test]
    async fn private_objects_have_validated_protected_acls() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("private");
        ensure_private_dir(&directory).await.unwrap();
        validate_private_path(&directory).await.unwrap();

        let file = directory.join("secret");
        drop(create_new_private(&file, true, true).unwrap());
        validate_private_path(&file).await.unwrap();
    }

    #[tokio::test]
    async fn hardlinked_secret_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("private");
        ensure_private_dir(&directory).await.unwrap();
        let file = directory.join("secret");
        drop(create_new_private(&file, true, true).unwrap());
        std::fs::hard_link(&file, directory.join("alias")).unwrap();
        assert!(validate_private_path(&file).await.is_err());
    }

    #[tokio::test]
    async fn permissive_acl_is_rejected_and_repaired() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("private");
        ensure_private_dir(&directory).await.unwrap();
        let file = directory.join("secret");
        drop(create_new_private(&file, true, true).unwrap());

        windows::set_null_dacl(&file).unwrap();
        assert!(validate_private_path(&file).await.is_err());
        set_private_file_permissions(&file).await.unwrap();
        validate_private_path(&file).await.unwrap();
    }

    #[tokio::test]
    async fn regular_file_is_not_accepted_as_private_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("not-a-directory");
        std::fs::write(&path, b"data").unwrap();
        assert_eq!(
            ensure_private_dir(&path).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
