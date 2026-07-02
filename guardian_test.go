package vpnclient

import (
	"testing"
	"time"
)

func TestDetectProxyPassClaimTimeOffsetLeavesStandardJWTTime(t *testing.T) {
	previousLocal := time.Local
	local := time.FixedZone("CST", 8*60*60)
	time.Local = local
	t.Cleanup(func() { time.Local = previousLocal })

	now := time.Date(2026, 7, 2, 22, 25, 50, 0, local)
	claims := ProxyPassClaims{
		Iat: now.Add(-time.Minute).Unix(),
		Nbf: now.Add(-time.Minute).Unix(),
		Exp: now.Add(10 * time.Minute).Unix(),
	}

	if got := detectProxyPassClaimTimeOffset(claims, now); got != 0 {
		t.Fatalf("expected no claim time correction, got %s", got)
	}
}

func TestDetectProxyPassClaimTimeOffsetCorrectsLocalWallClockJWTTime(t *testing.T) {
	previousLocal := time.Local
	local := time.FixedZone("CST", 8*60*60)
	time.Local = local
	t.Cleanup(func() { time.Local = previousLocal })

	now := time.Date(2026, 7, 2, 22, 25, 50, 0, local)
	rawNbf := time.Date(2026, 7, 2, 14, 25, 34, 0, local)
	rawExp := time.Date(2026, 7, 2, 14, 35, 34, 0, local)
	claims := ProxyPassClaims{
		Iat: rawNbf.Unix(),
		Nbf: rawNbf.Unix(),
		Exp: rawExp.Unix(),
	}

	got := detectProxyPassClaimTimeOffset(claims, now)
	if got != 8*time.Hour {
		t.Fatalf("expected 8h claim time correction, got %s", got)
	}

	pass := &ProxyPassInfo{
		Claims:          claims,
		claimTimeOffset: got,
	}
	if want := time.Date(2026, 7, 2, 22, 35, 34, 0, local); !pass.ExpiresAt().Equal(want) {
		t.Fatalf("expected corrected expiry %s, got %s", want, pass.ExpiresAt())
	}
}

func TestDetectProxyPassClaimTimeOffsetUsesIssuedAtWhenNotBeforeMissing(t *testing.T) {
	previousLocal := time.Local
	local := time.FixedZone("CST", 8*60*60)
	time.Local = local
	t.Cleanup(func() { time.Local = previousLocal })

	now := time.Date(2026, 7, 2, 22, 36, 51, 0, local)
	rawIat := time.Date(2026, 7, 2, 14, 36, 35, 0, local)
	rawExp := time.Date(2026, 7, 2, 14, 46, 35, 0, local)
	claims := ProxyPassClaims{
		Iat: rawIat.Unix(),
		Exp: rawExp.Unix(),
	}

	got := detectProxyPassClaimTimeOffset(claims, now)
	if got != 8*time.Hour {
		t.Fatalf("expected 8h claim time correction, got %s", got)
	}
}

func TestDetectProxyPassClaimTimeOffsetUsesExpiryWhenStartClaimsMissing(t *testing.T) {
	previousLocal := time.Local
	local := time.FixedZone("CST", 8*60*60)
	time.Local = local
	t.Cleanup(func() { time.Local = previousLocal })

	now := time.Date(2026, 7, 2, 22, 36, 51, 0, local)
	rawExp := time.Date(2026, 7, 2, 14, 46, 35, 0, local)
	claims := ProxyPassClaims{
		Exp: rawExp.Unix(),
	}

	got := detectProxyPassClaimTimeOffset(claims, now)
	if got != 8*time.Hour {
		t.Fatalf("expected 8h claim time correction, got %s", got)
	}
}

func TestDetectProxyPassClaimTimeOffsetLeavesFreshExpiryWithoutStartClaims(t *testing.T) {
	previousLocal := time.Local
	local := time.FixedZone("CST", 8*60*60)
	time.Local = local
	t.Cleanup(func() { time.Local = previousLocal })

	now := time.Date(2026, 7, 2, 22, 36, 51, 0, local)
	claims := ProxyPassClaims{
		Exp: now.Add(10 * time.Minute).Unix(),
	}

	if got := detectProxyPassClaimTimeOffset(claims, now); got != 0 {
		t.Fatalf("expected no claim time correction, got %s", got)
	}
}
