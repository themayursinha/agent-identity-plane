package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/themayursinha/agent-identity-plane/internal/registry"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

var version = "v0.3.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "visor-gateway":
		err = cmdVisorGateway(os.Args[2:])
	case "registry":
		if len(os.Args) < 3 || os.Args[2] != "lint" {
			err = fmt.Errorf("usage: agent-identity-plane registry lint <file>")
			break
		}
		err = cmdRegistryLint(os.Args[3:])
	case "token":
		if len(os.Args) < 3 {
			err = fmt.Errorf("usage: agent-identity-plane token inspect|verify ...")
			break
		}
		switch os.Args[2] {
		case "inspect":
			err = cmdTokenInspect(os.Args[3:])
		case "verify":
			err = cmdTokenVerify(os.Args[3:])
		default:
			err = fmt.Errorf("unknown token subcommand %s", os.Args[2])
		}
	case "trace":
		err = cmdTrace(os.Args[2:])
	case "keys":
		if len(os.Args) < 3 || os.Args[2] != "generate" {
			err = fmt.Errorf("usage: agent-identity-plane keys generate [-kid name] [-out file]")
			break
		}
		err = cmdKeysGenerate(os.Args[3:])
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
	case "-h", "-help", "--help", "help":
		usage()
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `agent-identity-plane %s

Commands:
  serve                 Run the STS (loopback default; SIGHUP reloads registry and keys)
  visor-gateway         Identity PEP in front of mcp-visor (verified --client-id)

  registry lint FILE    Strict-decode and validate a registry JSON file
  token inspect TOKEN   Decode a JWT without verifying the signature
  token verify ...      Verify a JWT against a JWKS and audience
  trace                 Reconstruct a txn from STS and visor JSONL logs
  keys generate         Write a new Ed25519 key file
  demo                  Run the multi-hop scenario and attack cases
  version               Print the version

`, version)
}

func cmdRegistryLint(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: agent-identity-plane registry lint <file>")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	issues := registry.Lint(b)
	if len(issues) > 0 {
		for _, i := range issues {
			fmt.Fprintln(os.Stderr, i)
		}
		return fmt.Errorf("registry lint failed")
	}
	fmt.Println("ok")
	return nil
}

func cmdTokenInspect(args []string) error {
	raw, err := tokenArg(args)
	if err != nil {
		return err
	}
	h, c, _, err := token.ParseUnverified(raw)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"header": h, "claims": c})
}

func cmdTokenVerify(args []string) error {
	var jwksPath, aud, iss, raw string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-jwks":
			i++
			if i >= len(args) {
				return fmt.Errorf("-jwks requires a path")
			}
			jwksPath = args[i]
		case "-aud":
			i++
			if i >= len(args) {
				return fmt.Errorf("-aud requires a value")
			}
			aud = args[i]
		case "-iss":
			i++
			if i >= len(args) {
				return fmt.Errorf("-iss requires a value")
			}
			iss = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag %s", args[i])
			}
			raw = args[i]
		}
	}
	if raw == "" || jwksPath == "" || aud == "" {
		return fmt.Errorf("usage: agent-identity-plane token verify -jwks FILE -aud AUD [-iss ISS] TOKEN")
	}
	b, err := os.ReadFile(jwksPath)
	if err != nil {
		return err
	}
	ks, err := token.ParseJWKS(b)
	if err != nil {
		return err
	}
	v := &verify.Verifier{Keys: ks, Issuer: iss}
	c, err := v.Verify(raw, aud)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

func tokenArg(args []string) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}
	if len(args) == 0 {
		b, err := os.ReadFile("/dev/stdin")
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("usage: agent-identity-plane token inspect TOKEN")
}

func cmdKeysGenerate(args []string) error {
	kid := "sts-1"
	out := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-kid":
			i++
			kid = args[i]
		case "-out":
			i++
			out = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	kf, err := token.GenerateEd25519(kid)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(out, b, 0o600)
}
