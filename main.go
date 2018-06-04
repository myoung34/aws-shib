package main

import "github.com/CUBoulder-OIT/aws-shib/cmd"

var (
	// This is updated via linker flags
	Version = "dev"
)

func main() {
	cmd.Execute(Version)
}
