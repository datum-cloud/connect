package daemonservice

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func rejectReparse(path string) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refuse reparse point in private daemon state path %s", path)
	}
	return nil
}

func windowsProgramData() string {
	path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err == nil && path != "" {
		return path
	}
	return `C:\ProgramData`
}

func secureServiceState(path string) error {
	parent := filepath.Dir(path)
	if parent == path {
		return fmt.Errorf("invalid daemon state path %s", path)
	}
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		if err := secureServiceState(parent); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err := rejectReparse(parent); err != nil {
		return err
	} else if strings.EqualFold(parent, filepath.Join(windowsProgramData(), "Datum")) {
		// A writable vendor parent could rename or replace its protected Connect
		// child. Validate it without rewriting unrelated ProgramData content.
		if err := validateTrustedWindowsPath(parent); err != nil {
			return fmt.Errorf("unsafe daemon state parent: %w", err)
		}
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if err := rejectReparse(path); err != nil {
		return err
	}
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse link in private daemon state path %s", current)
		}
		if err := rejectReparse(current); err != nil {
			return err
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("refuse non-regular entry in private daemon state path %s", current)
		}
		if !entry.IsDir() {
			if err := rejectHardlink(current); err != nil {
				return err
			}
		}
		return applyPrivateACL(current, entry.IsDir())
	})
}

func securePrivateFile(path string) error {
	if err := rejectReparse(path); err != nil {
		return err
	}
	if err := rejectHardlink(path); err != nil {
		return err
	}
	return applyPrivateACL(path, false)
}

func rejectHardlink(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("refuse hard-linked private daemon state path %s", path)
	}
	return nil
}

func applyPrivateACL(path string, directory bool) error {
	// FILE_ALL_ACCESS is used instead of the generic access bit so the stored
	// ACL is stable and can be validated consistently by the Rust daemon.
	const fileAllAccess = 0x1f01ff
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 2)
	for _, sid := range []*windows.SID{system, admins} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID,
				TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build private Windows ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, acl, nil); err != nil {
		return fmt.Errorf("secure Windows path %s: %w", path, err)
	}
	return nil
}
