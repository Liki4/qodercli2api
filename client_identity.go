package main

import (
	"net/http"
	"runtime"
	"strings"
)

// These final HTTP-layer helpers mutate only an owned header map. Callers clone
// prepared/caller headers first; the raw protocol output and signature stay intact.
func applyCommonClientIdentity(header http.Header) http.Header {
	if header == nil {
		header = make(http.Header)
	}
	for _, field := range []struct{ name, value string }{
		{"Cosy-Version", qoderProtocolVersion},
		{"Cosy-ClientType", defaultProtocolScene().ClientType},
		{"Cosy-MachineOS", clientMachineOS(runtime.GOOS, runtime.GOARCH)},
	} {
		present := false
		for key := range header {
			if strings.EqualFold(key, field.name) {
				present = true
				break
			}
		}
		if !present {
			header.Set(field.name, field.value)
		}
	}
	return header
}

func applyInferenceClientIdentity(header http.Header) http.Header {
	if header == nil {
		header = make(http.Header)
	}
	// The verified legacy JS wrapper removes both WASM fields, then overlays
	// UMID only when available. This adapter takes the no-UMID branch; machine
	// ID is not a substitute token and Cosy-MachineId remains untouched.
	for key := range header {
		if strings.EqualFold(key, "Cosy-MachineToken") || strings.EqualFold(key, "Cosy-MachineType") {
			delete(header, key)
		}
	}
	return header
}

// x86_64_linux is verified against 1.1.74. Other labels are portable adapter
// choices, not claimed captures: normalize common architecture names and macOS,
// and retain Go's names for other targets. No host or hardware probing is needed.
func clientMachineOS(goos, goarch string) string {
	switch goarch {
	case "amd64":
		goarch = "x86_64"
	case "arm64":
		goarch = "aarch64"
	case "386":
		goarch = "x86"
	}
	if goos == "darwin" {
		goos = "macos"
	}
	return goarch + "_" + goos
}
