package flow

import "net/http"

func resolveClientCredentials(req *http.Request) (clientId, clientSecret string) {
	var ok bool
	clientId, clientSecret, ok = req.BasicAuth()
	if !ok {
		clientId = req.FormValue("client_id")
		clientSecret = req.PostFormValue("client_secret")
	}
	return
}
