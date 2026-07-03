package main

import (
	"fmt"
	"io"
	"os"

	"github.com/mickamy/tapaside/internal/cli"
	"github.com/mickamy/tapaside/internal/exit"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "--version", "-version", "-v", "version":
			fmt.Fprintf(stdout, "tapaside %s\n", version)

			return exit.OK
		case "--help", "-help", "-h", "help":
			cli.PrintUsage(stdout)

			return exit.OK
		}
	}

	return cli.Run(args, stdout, stderr)
}
