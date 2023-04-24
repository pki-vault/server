package main

import (
	"fmt"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/pki-vault/server/cmd"
	"os"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
