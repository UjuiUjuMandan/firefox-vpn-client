package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

type Protocol struct {
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Scheme         string `json:"scheme,omitempty"`
	TemplateString string `json:"templateString,omitempty"`
}

type Server struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Protocols   []Protocol `json:"protocols"`
}

type City struct {
	Name    string   `json:"name"`
	Code    string   `json:"code"`
	Servers []Server `json:"servers"`
}

type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

type remoteSettingsRecord struct {
	ID   string `json:"id"`
	Data json.RawMessage
	// The record itself IS a Country when the collection stores one record per country
	Country
}

type remoteSettingsResponse struct {
	Data []json.RawMessage `json:"data"`
}

func fetchServerList() ([]Country, error) {
	resp, err := http.Get(remoteSettingsURL)
	if err != nil {
		return nil, fmt.Errorf("fetching server list: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading server list response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server list returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var rsResp remoteSettingsResponse
	if err := json.Unmarshal(body, &rsResp); err != nil {
		return nil, fmt.Errorf("parsing server list envelope: %w", err)
	}

	var countries []Country
	for _, raw := range rsResp.Data {
		var c Country
		if err := json.Unmarshal(raw, &c); err != nil {
			// If it doesn't parse as a Country, skip it
			continue
		}
		if c.Code != "" && len(c.Cities) > 0 {
			countries = append(countries, c)
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
