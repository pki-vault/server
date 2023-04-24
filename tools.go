//go:build tools
// +build tools

package main

import (
	_ "github.com/deepmap/oapi-codegen/cmd/oapi-codegen"
	_ "github.com/google/wire/cmd/wire"
	_ "github.com/joho/godotenv"
	_ "github.com/volatiletech/sqlboiler/v4/boilingcore"
)
