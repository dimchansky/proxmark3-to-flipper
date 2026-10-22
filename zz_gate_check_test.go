package main

import "testing"

// Temporary: verifies that CI Required fails when a required job fails.
func TestGateCheckDeliberateFailure(t *testing.T) { t.Fatal("deliberate failure") }
