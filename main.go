package main

import "***REMOVED***/aws-shib/cmd"

var (
	// This is updated via linker flags
	Version = "dev"
)

func main() {
	cmd.Execute(Version)
}
