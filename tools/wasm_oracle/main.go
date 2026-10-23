package main

import (
	"context"
	"io"
	"os"
)

type commandArgs struct{ wasmPath, fixturePath, command, version, outputPath string }

func parseArgs(args []string) (commandArgs, error) {
	var result commandArgs
	for len(args) > 0 && args[0] != "verify-fixtures" && args[0] != "validate-fixtures" && args[0] != "capture-fixtures" {
		if len(args) < 2 {
			return result, fail("arguments")
		}
		switch args[0] {
		case "--wasm":
			result.wasmPath = args[1]
		case "--fixtures":
			result.fixturePath = args[1]
		case "--version":
			result.version = args[1]
		case "--output":
			result.outputPath = args[1]
		default:
			return result, fail("arguments")
		}
		args = args[2:]
	}
	if len(args) != 1 || result.fixturePath == "" {
		return result, fail("arguments")
	}
	result.command = args[0]
	switch result.command {
	case "capture-fixtures":
		if result.wasmPath == "" || result.outputPath == "" || result.version != upgradeVersion {
			return result, fail("arguments")
		}
	case "verify-fixtures", "validate-fixtures":
		if result.version != "" || result.outputPath != "" {
			return result, fail("arguments")
		}
		if (result.command == "verify-fixtures") != (result.wasmPath != "") {
			return result, fail("arguments")
		}
	default:
		return result, fail("arguments")
	}
	return result, nil
}
func run(ctx context.Context, args []string, out io.Writer) int {
	parsed, err := parseArgs(args)
	if err != nil {
		emitStatus(out, statusLine{"verify-fixtures", "unavailable", "FAIL", categoryOf(err)})
		return 2
	}
	failed := func(err error) int {
		emitStatus(out, statusLine{parsed.command, "unavailable", "FAIL", categoryOf(err)})
		return 1
	}
	policy, err := policyForDirectory(parsed.fixturePath)
	if err != nil {
		return failed(err)
	}
	if parsed.command == "capture-fixtures" && policy.Identity != pinnedPolicy().Identity {
		return failed(fail("capture-seed-identity"))
	}
	fixtures, err := validateFixtureSet(parsed.fixturePath, policy)
	if err != nil {
		return failed(err)
	}
	if parsed.command == "validate-fixtures" {
		emitStatus(out, statusLine{"validate-fixtures", "static", "PASS", ""})
		return 0
	}
	if parsed.command == "capture-fixtures" {
		policy, _ = policyForVersion(parsed.version)
	}
	source, err := readBoundedRegularFile(parsed.wasmPath, int64(policy.Identity.Size), "wasm-read")
	if err == nil {
		err = validateWASMForIdentity(source, policy.Identity)
	}
	if err != nil {
		return failed(err)
	}
	if parsed.command == "capture-fixtures" {
		captured, err := captureFixtures(ctx, source, fixtures, policy.Identity)
		if err != nil {
			return failed(err)
		}
		if err := writeCapturedFixtures(parsed.outputPath, captured, policy.Identity); err != nil {
			return failed(err)
		}
		emitStatus(out, statusLine{"capture-fixtures", "recorded-and-replayed", "PASS", ""})
		return 0
	}
	if _, err = verifyFixtures(ctx, source, fixtures, out); err != nil {
		return failed(err)
	}
	return 0
}
func guarded(out io.Writer, action func() int) (status int) {
	defer func() {
		if recover() != nil {
			emitStatus(out, statusLine{"verify-fixtures", "unavailable", "FAIL", "internal"})
			status = 1
		}
	}()
	return action()
}

func main() {
	os.Exit(guarded(os.Stdout, func() int {
		return run(context.Background(), os.Args[1:], os.Stdout)
	}))
}
