package main

import (
	"fmt"
	"os"

	"github.com/bovinemagnet/wg-dns-sync/internal/app"
)

func main() {
	if err := app.NewRootCommand().Execute(); err != nil {
		if exitErr, ok := err.(app.ExitError); ok {
			fmt.Fprintln(os.Stderr, exitErr.Error())
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(app.ExitCodeGeneral)
	}
}
