package flow

import (
	"net/http"
	"strings"
)

// resolveClientCredentials will extract the clientid and secret from the basic header
// or if not present it tries to get it form the post body
func resolveClientCredentials(req *http.Request) (clientId, clientSecret string) {
	var ok bool
	clientId, clientSecret, ok = req.BasicAuth()
	if !ok {
		clientId = req.FormValue("client_id")
		clientSecret = req.PostFormValue("client_secret")
	}
	return
}

// hasRedirectUri checks the base uri matches one of the provided uri's
func hasRedirectUri(uris []string, uri string) bool {
	for _, baseUri := range uris {
		if strings.HasPrefix(uri, baseUri) {
			return true
		}
	}
	return false
}
