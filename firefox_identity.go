package vpnclient

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Updated from Mozilla's stable-release metadata by the version-update workflow.
// Keep this pinned: authentication must not depend on a version lookup at startup.
const defaultFirefoxVersion = "159.0"

// Use one desktop identity even on routers; do not invent architecture-specific
// Firefox variants. This matches the desktop Linux platform in nsHttpHandler.cpp.
func defaultFirefoxUserAgent() string {
	major, _, _ := strings.Cut(defaultFirefoxVersion, ".")
	return fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64; rv:%s.0) Gecko/20100101 Firefox/%s", major, defaultFirefoxVersion)
}

var fxaUserAgentOverride atomic.Pointer[string]

// SetFxAUserAgent overrides the identity used by both FxA API requests and the
// Fastly challenge solver. An empty value restores the pinned Firefox default.
// Call before issuing any control-plane requests and keep the identity unchanged
// for the process lifetime: challenge cookies may be tied to the client identity.
// Guardian and Remote Settings headers are unaffected.
func SetFxAUserAgent(userAgent string) error {
	if userAgent == "" {
		fxaUserAgentOverride.Store(nil)
		return nil
	}
	for _, c := range userAgent {
		if c < 0x20 || c > 0x7e {
			return fmt.Errorf("FxA user agent must contain only printable ASCII characters")
		}
	}
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return fmt.Errorf("FxA user agent must not contain only spaces")
	}
	fxaUserAgentOverride.Store(&userAgent)
	return nil
}

func fxaUserAgent() string {
	if override := fxaUserAgentOverride.Load(); override != nil {
		return *override
	}
	return defaultFirefoxUserAgent()
}
