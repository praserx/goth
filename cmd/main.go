package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "Aegis",
		Usage: "Aegis is a security-focused application",
		Flags: []cli.Flag{
			flagVerbose,
			flagListenHTTP,
			flagListenHTTPS,
			flagTLSCert,
			flagTLSKey,
			flagTLSSkipVerify,
			flagDiscoveryURL,
			flagClientID,
			flagClientSecret,
			flagUpstreamURL,
			flagPolicyMode,
		},
		UseShortOptionHandling: true,
		// This is the main action that will be executed when the command is run
		Action: func(context.Context, *cli.Command) error {
			fmt.Println("boom! I say!")
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
