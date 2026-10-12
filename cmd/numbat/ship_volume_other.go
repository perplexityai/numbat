//go:build !darwin

package main

import "os"

func shipVolumeIdentity(*os.File) (string, error) { return "", nil }
