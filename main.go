package main

import "***REMOVED***/icbs/aws-shib/cmd"

var (
	// This is updated via linker flags
	Version = "dev"
)

func main() {
	cmd.Execute(Version)
}
