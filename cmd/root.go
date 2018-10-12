package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Errors returned from frontend commands
var (
	ErrCommandMissing         = errors.New("must specify command to run")
	ErrTooManyArguments       = errors.New("too many arguments")
	ErrTooFewArguments        = errors.New("too few arguments")
	ErrFailedToSetCredentials = errors.New("Failed to set credentials in your keyring")
)

// global flags
var (
	backend string
	debug   bool
	version string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:              "aws-shib",
	Short:            "aws-shib allows you to authenticate with AWS using your adfs credentials",
	SilenceUsage:     true,
	SilenceErrors:    true,
	PersistentPreRun: prerun,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(vers string) {
	version = vers
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		switch err {
		case ErrTooFewArguments, ErrTooManyArguments:
			RootCmd.Usage()
		}
		os.Exit(1)
	}
}

func prerun(cmd *cobra.Command, args []string) {
	// Load backend from env var if not set as a flag
	if !cmd.Flags().Lookup("backend").Changed {
		backendFromEnv, ok := os.LookupEnv("AWS_OKTA_BACKEND")
		if ok {
			backend = backendFromEnv
		}
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}
}

func init() {
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}
	RootCmd.PersistentFlags().StringVarP(&backend, "backend", "b", "", fmt.Sprintf("Secret backend to use %s", backendsAvailable))
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
}
