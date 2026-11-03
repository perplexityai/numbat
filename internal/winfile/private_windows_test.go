//go:build windows

package winfile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectedDescriptor(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, tc := range []struct {
		name, extra             string
		secret, directory, want bool
	}{
		{"private", "", true, false, true},
		{"public config", "(A;;GR;;;WD)", false, false, true},
		{"public secret", "(A;;GR;;;WD)", true, false, false},
		{"writable config", "(A;;GW;;;WD)", false, false, false},
		{"replaceable parent", "(A;;0x40;;;WD)", false, true, false},
		{"readable parent", "(A;;GR;;;WD)", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")" + tc.extra)
			if err != nil {
				t.Fatal(err)
			}
			if got := checkDescriptor(sd, tc.secret, tc.directory); (got == nil) != tc.want {
				t.Fatalf("descriptor result = %v", got)
			}
		})
	}
}

func TestPrivateStateCreationAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := PrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "state.db")
	f, err := OpenPrivate(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = OpenPrivate(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := CheckProtected(f, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != "synthetic" {
		t.Fatalf("reopen: %q %v", data, err)
	}
}
