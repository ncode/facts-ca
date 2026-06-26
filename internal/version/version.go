// Package version holds the build version, injected at release time via
// -ldflags "-X github.com/ncode/facts-ca/internal/version.Version=<tag>".
package version

// Version is the build version ("dev" for untagged local builds).
var Version = "dev"
