//go:build tribescan_lab

package main

// Scan lab (local end-to-end run, never in a product archive: build tag tribescan_lab). The
// production archive verifies the probe host's TLS with the system roots only; a loopback lab has
// no publicly trusted certificate, so this file sets the engine's existing test seam
// (tribeScanTestRootCAs, the same one tribescan_test.go sets) from the PEM file named by
// TRIBE_SCAN_LAB_ROOTS. Nothing else of the engine differs from the conan package's source.

import (
	"crypto/x509"
	"os"
)

func init() {
	path := os.Getenv("TRIBE_SCAN_LAB_ROOTS")
	if path == "" {
		return
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		panic("scan lab: cannot read TRIBE_SCAN_LAB_ROOTS: " + err.Error())
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		panic("scan lab: no certificate in TRIBE_SCAN_LAB_ROOTS")
	}
	tribeScanTestRootCAs = pool
}
