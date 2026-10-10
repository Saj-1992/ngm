// Package api embeds the OpenAPI contract.
package api

import _ "embed"

// OpenAPI is the machine-readable API contract (api/openapi.json).
//
//go:embed openapi.json
var OpenAPI []byte
