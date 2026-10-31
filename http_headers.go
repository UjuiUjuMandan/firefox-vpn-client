package vpnclient

import "net/http"

const mozillaVPNUserAgent = "MozillaVPN/2.35.0 (sys:linux; iap:true)"

func applyFxAHeaders(req *http.Request) {
	req.Header.Set("User-Agent", fxaUserAgent())
	req.Header.Set("Accept", "application/json")
}

func applyMozillaVPNHeaders(req *http.Request) {
	req.Header.Set("User-Agent", mozillaVPNUserAgent)
	req.Header.Set("Accept", "application/json")
}
