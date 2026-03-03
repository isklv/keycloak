package clientcred

import "net/http"

type RoundTripper struct {
	Base http.RoundTripper
	TS   TokenSource
}

func (rt RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := rt.TS.Token(req.Context())
	if err != nil {
		return nil, err
	}

	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	return rt.Base.RoundTrip(r2)
}

func NewHTTPClient(ts TokenSource) *http.Client {
	return &http.Client{
		Transport: RoundTripper{
			Base: http.DefaultTransport,
			TS:   ts,
		},
	}
}
