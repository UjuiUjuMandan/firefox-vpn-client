package vpnclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

//nolint:lll // single Remote Settings URL literal; splitting it would only hurt grep-ability
const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

// errServerListStatus signals a non-OK Remote Settings response.
var errServerListStatus = errors.New("server list returned an error status")

// Protocol is one connection protocol entry of a VPN server.
type Protocol struct {
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Scheme         string `json:"scheme,omitempty"`
	TemplateString string `json:"templateString,omitempty"` //nolint:tagliatelle // upstream wire format
}

// Server is one VPN server instance with its supported protocols.
type Server struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Protocols   []Protocol `json:"protocols"`
}

// City groups the servers of one VPN location.
type City struct {
	Name    string   `json:"name"`
	Code    string   `json:"code"`
	Servers []Server `json:"servers"`
}

// Country groups the cities of one VPN country.
type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

type remoteSettingsResponse struct {
	Data []json.RawMessage `json:"data"`
}

func fetchServerList(ctx context.Context) ([]Country, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteSettingsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating server list request: %w", err)
	}

	applyMozillaVPNHeaders(req)

	resp, err := doControlPlane(req)
	if err != nil {
		return nil, fmt.Errorf("fetching server list: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d: %s", errServerListStatus, resp.StatusCode, readErrorBody(resp.Body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading server list response: %w", err)
	}

	var rsResp remoteSettingsResponse

	err = json.Unmarshal(body, &rsResp)
	if err != nil {
		return nil, fmt.Errorf("parsing server list envelope: %w", err)
	}

	var countries []Country

	for _, raw := range rsResp.Data {
		var country Country

		err := json.Unmarshal(raw, &country)
		if err != nil {
			// If it doesn't parse as a Country, skip it
			continue
		}

		if country.Code != "" && len(country.Cities) > 0 {
			countries = append(countries, country)
		}
	}

	return countries, nil
}

func printServerList(countries []Country) {
	for _, country := range countries {
		fmt.Printf("\n=== %s (%s) ===\n", country.Name, country.Code)

		for _, city := range country.Cities {
			fmt.Printf("  City: %s (%s)\n", city.Name, city.Code)

			for _, srv := range city.Servers {
				if srv.Quarantined {
					fmt.Printf("    [QUARANTINED] %s:%d\n", srv.Hostname, srv.Port)

					continue
				}

				fmt.Printf("    Server: %s:%d\n", srv.Hostname, srv.Port)

				for _, proto := range srv.Protocols {
					switch proto.Name {
					case "connect":
						scheme := proto.Scheme
						if scheme == "" {
							scheme = "https"
						}

						fmt.Printf("      Protocol: CONNECT (%s) -> %s:%d\n", scheme, proto.Host, proto.Port)
					case "masque":
						fmt.Printf("      Protocol: MASQUE -> %s:%d (template: %s)\n", proto.Host, proto.Port, proto.TemplateString)
					default:
						fmt.Printf("      Protocol: %s -> %s:%d\n", proto.Name, proto.Host, proto.Port)
					}
				}

				if len(srv.Protocols) == 0 {
					fmt.Printf("      Protocol: CONNECT (https) -> %s:%d (default)\n", srv.Hostname, srv.Port)
				}
			}
		}
	}
}

// FetchServerList fetches the Mozilla VPN server list from Remote Settings.
func FetchServerList(ctx context.Context) ([]Country, error) {
	return fetchServerList(ctx)
}

// PrintServerList prints the server list to stdout in the demo format.
func PrintServerList(countries []Country) {
	printServerList(countries)
}
