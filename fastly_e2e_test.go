package vpnclient

import (
	"context"
	"errors"
	"os"
	"testing"
)

// TestSolveFastlyChallengeE2E exercises the real Fastly challenge flow and
// proves the solved cookie lets API requests pass the edge. It hits live
// infrastructure, so it only runs when FXA_E2E=1 is set.
func TestSolveFastlyChallengeE2E(t *testing.T) {
	if os.Getenv("FXA_E2E") != "1" {
		t.Skip("set FXA_E2E=1 to run the live Fastly challenge test")
	}

	ctx := context.Background()
	if err := solveFastlyChallenge(ctx); err != nil {
		t.Fatalf("solveFastlyChallenge failed: %v", err)
	}

	// A dummy login must now reach the FxA origin: it should fail with a
	// proper FxA error (e.g. unknown account), not with HTTP 406.
	_, err := fxaLogin(ctx, "nonexistent-user-e2e@example.invalid", "dummy-password")
	var apiErr *fxaAPIError
	if !errors.As(err, &apiErr) || apiErr.Status == 406 || apiErr.Errno == 0 {
		t.Fatalf("expected an FxA origin error after solving, got %v", err)
	}
	t.Logf("dummy login result: %v", err)
}

// TestFxARefreshE2E checks the default identity without loading or saving real
// credentials. An invalid refresh token must reach FxA, not fail at the edge.
func TestFxARefreshE2E(t *testing.T) {
	if os.Getenv("FXA_E2E") != "1" {
		t.Skip("set FXA_E2E=1 to run the live FxA refresh test")
	}
	_, err := fxaRefreshToken(context.Background(), "invalid-diagnostic-token")
	var apiErr *fxaAPIError
	if !errors.As(err, &apiErr) || apiErr.Status == 406 || apiErr.Errno == 0 {
		t.Fatalf("expected an FxA origin error, got %v", err)
	}
	t.Logf("dummy refresh reached FxA: HTTP %d, errno %d", apiErr.Status, apiErr.Errno)
}
