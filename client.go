package oauth2

import (
	"strings"
)

type ClientId string

type Client struct {
	ClientId     ClientId
	ClientSecret string
	Name         string
	RedirectUri  []string
	Scope        Scope
}

// HasRedirectUri checks the base uri matches one of the registered uri's
func (c *Client) HasRedirectUri(uri string) bool {
	for _, baseUri := range c.RedirectUri {
		if strings.HasPrefix(uri, baseUri) {
			return true
		}
	}
	return false
}
