package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	version = "0.3.0"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and exit",
	Run: func(cmd *cobra.Command, args []string) {
		printVersion()
	},
}

func init() {
	mainCmd.AddCommand(versionCmd)
}

func printVersion() {
	fmt.Println(version)
	os.Exit(0)
}
