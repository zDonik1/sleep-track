package docs

import (
	_ "embed"
)

//go:embed openapi.yaml
var ApiYaml []byte
