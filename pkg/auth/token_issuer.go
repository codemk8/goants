package auth

import (
	"net/http"

	"codemk8/goants/pkg/token"

	"github.com/golang/glog"
)

type TokenIssuer struct {
}

func (lti *TokenIssuer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	user, password, ok := req.BasicAuth()
	if !ok {
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}
	// TODO authenticate here!

	// Auth was successful, create token
	token := lti.createToken(ldapEntry)

	// Sign token and return
	signedToken, err := lti.TokenSigner.Sign(token)
	if err != nil {
		glog.Errorf("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func (lti *TokenIssuer) createToken(ldapEntry *goldap.Entry) *token.AuthToken {
	return &token.AuthToken{
		Username:   ldapEntry.DN,
		Assertions: map[string]string{
			//"user":
			//"issuer":
			//"expire":
		},
	}
}
