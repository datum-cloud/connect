package daemonservice

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validatePrivilegedExecutable(path string) error {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		return fmt.Errorf("ProgramFiles is unavailable; cannot verify the Windows service executable trust boundary")
	}
	rel, err := filepath.Rel(programFiles, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("refuse unsafe Windows system-service executable %s: install the daemon under Program Files", path)
	}
	for current := path; ; current = filepath.Dir(current) {
		if err := rejectReparse(current); err != nil {
			return err
		}
		if err := validateTrustedWindowsPath(current); err != nil {
			return fmt.Errorf("refuse unsafe Windows system-service executable path: %w", err)
		}
		if strings.EqualFold(current, filepath.Clean(programFiles)) {
			break
		}
	}
	return nil
}

func validateTrustedWindowsPath(path string) error {
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		return err
	}
	trusted := []*windows.SID{system, admins, trustedInstaller}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !sidIn(owner, trusted) {
		return fmt.Errorf("%s has an untrusted owner %s", path, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no trustworthy DACL", path)
	}
	const unsafeWrite = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | 0x40
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		// Object and callback allow ACEs have different layouts and semantics.
		// They are uncommon on program binaries; reject them instead of risking
		// an unexamined write grant. Types 5, 9, and 11 are the allowed forms.
		if ace.Header.AceType == 5 || ace.Header.AceType == 9 || ace.Header.AceType == 11 {
			return fmt.Errorf("%s contains an unsupported allow ACE type %d", path, ace.Header.AceType)
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && ace.Mask&unsafeWrite != 0 {
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sidIn(sid, trusted) {
				return fmt.Errorf("%s grants write access to untrusted principal %s", path, sid)
			}
		}
	}
	return nil
}

func sidIn(candidate *windows.SID, allowed []*windows.SID) bool {
	for _, sid := range allowed {
		if sid != nil && candidate.Equals(sid) {
			return true
		}
	}
	return false
}
