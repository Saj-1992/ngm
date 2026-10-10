// Package deploy embeds installation assets (systemd units, tmpfiles).
package deploy

import "embed"

// Systemd holds the unit files and tmpfiles configuration.
//
//go:embed systemd/*
var Systemd embed.FS
