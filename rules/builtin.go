// Package rules embeds Numbat's built-in rule catalog.
//
// The YAML files in this directory are ordinary Numbat rule files and remain
// the authoritative source. The binary also embeds generated CEL checked
// expressions to reduce startup work for the immutable built-in catalog.
package rules

import "embed"

//go:generate go run ./internal/rulegen -rules . -out internal/checked

// FS contains the authoritative built-in YAML catalog.
//
//go:embed */*.yaml
var FS embed.FS

// CheckedFS contains generated checked expressions for the built-in catalog.
//
//go:embed internal/checked/*.pb
var CheckedFS embed.FS

// Dir is the directory within FS that holds the embedded rule files.
const Dir = "."

// CheckedDir is the generated catalog path within CheckedFS.
const CheckedDir = "internal/checked"
