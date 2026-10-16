package rule

import "testing"

func TestCanonicalPath(t *testing.T) {
	cases := map[string]string{
		"":                                         "",
		"numbat.ts":                                "numbat.ts",
		"/etc/sudoers.d/agent":                     "/etc/sudoers.d/agent",
		"/etc/sudoers.d/./agent":                   "/etc/sudoers.d/agent",
		"/etc//sudoers.d/agent":                    "/etc/sudoers.d/agent",
		"/etc/sudoers.d/x/../agent":                "/etc/sudoers.d/agent",
		"/etc/sudoers.d/../sudoers":                "/etc/sudoers",
		"/../etc/sudoers":                          "/etc/sudoers",
		"/proc/self/root/etc/sudoers":              "/etc/sudoers",
		"/proc/4321/task/8765/root/etc/sudoers":    "/etc/sudoers",
		"/proc/thread-self/root":                   "/",
		"/proc/self/rootfs/etc/sudoers":            "/proc/self/rootfs/etc/sudoers",
		"~/.ssh/./authorized_keys":                 "~/.ssh/authorized_keys",
		"~//.ssh//authorized_keys":                 "~/.ssh/authorized_keys",
		"$HOME//.ssh/authorized_keys":              "$HOME/.ssh/authorized_keys",
		"$HOME/x/../.ssh/authorized_keys":          "$HOME/.ssh/authorized_keys",
		"~/../~/.ssh/authorized_keys":              "~/../~/.ssh/authorized_keys",
		"x/../~/.ssh/authorized_keys":              "x/../~/.ssh/authorized_keys",
		"C:/Users/dev/x/../.ssh/authorized_keys":   "C:/Users/dev/.ssh/authorized_keys",
		"C:/../C:/Users/dev/.ssh/authorized_keys":  "C:/../C:/Users/dev/.ssh/authorized_keys",
		"-f=/etc/sudoers.d/../sudoers":             "-f=/etc/sudoers",
		"-f=/../etc/sudoers":                       "-f=/etc/sudoers",
		"--file=/proc/self/root/etc/sudoers":       "--file=/etc/sudoers",
		"/proc/self/root/proc/1/root/etc/sudoers":  "/etc/sudoers",
		"FILE=~//.ssh/authorized_keys":             "FILE=~/.ssh/authorized_keys",
		"/proc//self/root/etc/sudoers":             "/etc/sudoers",
		"/proc/./self/root/etc/sudoers":            "/etc/sudoers",
		"/etc/../proc/self/root/etc/sudoers":       "/etc/sudoers",
		"/proc/4321/task/./8765/root/etc/sudoers":  "/etc/sudoers",
		"/proc/self/root/../etc/sudoers":           "/etc/sudoers",
		"-f=/proc//self/root/etc/sudoers":          "-f=/etc/sudoers",
		"/etc/$PART/../sudoers":                    "/etc/$PART/../sudoers",
		"/home/$OTHER/../dev/.ssh/authorized_keys": "/home/$OTHER/../dev/.ssh/authorized_keys",
		"$HOME/$OTHER/../.ssh/authorized_keys":     "$HOME/$OTHER/../.ssh/authorized_keys",
		"/etc/`id`/../sudoers":                     "/etc/`id`/../sudoers",
	}
	for in, want := range cases {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}
