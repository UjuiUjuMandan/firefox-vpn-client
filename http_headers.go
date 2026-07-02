package vpnclient

import "net/http"

const mozillaVPNUserAgent = "MozillaVPN/2.35.0 (sys:linux; iap:true)"

func applyMozillaVPNHeaders(req *http.Request) {
	req.Header.Set("User-Agent", mozillaVPNUserAgent)
	req.Header.Set("Accept", "application/json")
}
