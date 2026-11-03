//go:build windows

package winfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckProtectedParents rejects redirecting or replaceable ancestors. Creating
// an unrelated sibling is harmless; deleting or rewriting this path is not.
func CheckProtectedParents(path string) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("protected directory %q unavailable or redirecting", dir)
		}
		sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		if err := checkDescriptor(sd, false, true); err != nil {
			return fmt.Errorf("protected directory %q: %w", dir, err)
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}

// CheckProtected validates the opened object, not a second pathname lookup.
func CheckProtected(f *os.File, secret bool) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkDescriptor(sd, secret, false)
}

func checkDescriptor(sd *windows.SECURITY_DESCRIPTOR, secret, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	installer, _, _, _ := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user.User.Sid) ||
			sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
			installer != nil && sid.Equals(installer))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return errors.New("owner must be the current user or a system administrator")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("explicit access control is required")
	}
	unsafeMask := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE)
	if directory {
		unsafeMask |= 0x0040 // FILE_DELETE_CHILD
	} else {
		unsafeMask |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	if secret {
		unsafeMask |= windows.GENERIC_READ | windows.FILE_READ_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// Conditional/object-specific grants are not part of this deliberately
		// narrow private-file policy; do not guess their effective permissions.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported access-control grant")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted(sid) && uint32(ace.Mask)&unsafeMask != 0 {
			return errors.New("access control grants other users protected access")
		}
	}
	return nil
}

func privateAttributes() (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd,
	}, nil
}

// PrivateDirectory creates only the requested directory with a protected DACL.
// Existing directories are verified rather than silently changing permissions.
func PrivateDirectory(path string) error {
	attrs, err := privateAttributes()
	if err != nil {
		return err
	}
	path, err = extendedPath(path)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, attrs); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private directory unavailable or redirecting")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkDescriptor(sd, true, false)
}

// OpenPrivate creates an empty read/write state file with a protected DACL.
func OpenPrivate(path string) (*os.File, error) {
	attrs, err := privateAttributes()
	if err != nil {
		return nil, err
	}
	path, err = extendedPath(path)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, attrs,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err == nil &&
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		err = errors.New("private file must be regular and not a reparse point")
	}
	if err == nil {
		err = CheckProtected(f, true)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
