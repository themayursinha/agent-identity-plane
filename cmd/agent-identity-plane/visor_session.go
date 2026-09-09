package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/visorsession"
)

func cmdVisorSession(args []string) error {
	fs := flag.NewFlagSet("visor-session", flag.ContinueOnError)
	gateway := fs.String("gateway", "", "visor-gateway identity-only URL (https, or loopback http)")
	tok := fs.String("token", "", "STS access token (or AIP_ACCESS_TOKEN)")
	dpopKey := fs.String("dpop-key", "", "0600 Ed25519 key file used for DPoP")
	visorBin := fs.String("visor-bin", "mcp-visor", "mcp-visor binary")
	printOnly := fs.Bool("print", false, "print argv and exit without exec")
	if err := fs.Parse(args); err != nil {
		return err
	}
	extra := fs.Args()
	if err := visorsession.RejectIdentityArgs(extra); err != nil {
		return err
	}
	if *gateway == "" || *dpopKey == "" {
		return fmt.Errorf("usage: agent-identity-plane visor-session -gateway URL -dpop-key FILE [-token JWT] [-visor-bin mcp-visor] [-print] -- [visor flags]")
	}
	token := *tok
	if token == "" {
		token = os.Getenv(visorsession.AccessTokenEnv)
	}
	kf, err := visorsession.LoadProofKey(*dpopKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := visorsession.Fetch(ctx, visorsession.Request{
		GatewayURL: *gateway,
		Token:      token,
		ProofKey:   kf,
	})
	if err != nil {
		return err
	}
	name, argv, err := visorsession.Command(*visorBin, m, extra)
	if err != nil {
		return err
	}
	if *printOnly {
		fmt.Println(visorsession.FormatArgv(name, argv))
		return nil
	}
	return execVisor(name, argv)
}
