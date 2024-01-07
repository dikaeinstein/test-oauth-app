package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

const addr = "localhost:8080"

func main() {
	githubClientID := os.Getenv("GITHUB_CLIENT_ID")
	githubClientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	if githubClientID == "" || githubClientSecret == "" {
		slog.Error("Set GITHUB_CLIENT_* env vars")
		os.Exit(1)
	}

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/login", loginHandler(githubClientID))
	http.HandleFunc("/github/callback", githubCallbackHandler(githubClientID, githubClientSecret))

	slog.Info("Listening on...", slog.String("addr", addr))
	panic(http.ListenAndServe(addr, nil))
}

const rootHTML = `
<html>
	<head>
		<title>GitHub OAuth</title>
	</head>
	<body>
		<h1>My OAuth App</h1>
		<p>Using raw HTTP OAuth 2.0</p>
		<p>Click the button below to login with GitHub</p>
		<button><a href="/login">Login with GitHub</a></button>
	</body>
</html>
`

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, rootHTML)
}

func loginHandler(ghClientID string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Request a user's GitHub identity
		//
		// ... by redirecting the user's browser to a GitHub login endpoint. We're not
		// setting redirect_uri, leaving it to GitHub to use the default we set for
		// this application: /github/callback
		// We're also not asking for any specific scope, because we only need access
		// to the user's public information to know that the user is really logged in.
		//
		// We're setting a random state cookie for the client to return
		// to us when the call comes back, to prevent CSRF per
		// section 10.12 of https://www.rfc-editor.org/rfc/rfc6749.html

		state, err := randString(16)
		if err != nil {
			slog.Error("Failed to generate state", slog.String("err", err.Error()))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "state",
			Value:    state,
			Path:     "/",
			MaxAge:   int(time.Hour.Seconds()),
			Secure:   r.TLS != nil,
			HttpOnly: true,
		})

		redirectURL := fmt.Sprintf(
			"https://github.com/login/oauth/authorize?client_id=%s&state=%s",
			ghClientID,
			state,
		)
		http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
	}
}

type ghResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func githubCallbackHandler(ghClientID, ghClientSecret string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Step 2: Users are redirected back to your site by GitHub
		//
		// The user is authenticated w/ GitHub by this point, and GH provides us
		// a temporary code we can exchange for an access token using the app's
		// full credentials.
		//
		// Start by checking the state returned by GitHub matches what
		// we've stored in the cookie.

		stateCookie, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state cookie not found", http.StatusBadRequest)
			return
		}

		if r.URL.Query().Get("state") != stateCookie.Value {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}

		// exchange the authorization code for an access token
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "code not found", http.StatusBadRequest)
			return
		}

		reqBody := map[string]string{
			"client_id":     ghClientID,
			"client_secret": ghClientSecret,
			"code":          code,
		}
		reqBodyJSON, err := json.Marshal(reqBody)
		if err != nil {
			slog.Error("Failed to marshal Oauth 2.0 Access token request body", slog.String("err", err.Error()))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		req, err := http.NewRequest(
			http.MethodPost,
			"https://github.com/login/oauth/access_token",
			bytes.NewBuffer(reqBodyJSON),
		)
		if err != nil {
			slog.Error("Failed to create Oauth 2.0 Access token request", slog.String("err", err.Error()))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "unable to connect to access_token endpoint", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "unable to exchange code for access token", http.StatusInternalServerError)
			return
		}

		respBody, _ := io.ReadAll(resp.Body)
		var ghResp ghResponse
		if err := json.Unmarshal(respBody, &ghResp); err != nil {
			http.Error(w, "unable to parse access token response", http.StatusInternalServerError)
			return
		}

		// Step 3: Use the access token to access the API
		//
		// With the access token in hand, we can access the GitHub API on behalf
		// of the user. Since we didn't provide a scope, we only get access to
		// the user's public information.
		userInfo, err := getGitHubUserInfo(ghResp.AccessToken)
		if err != nil {
			http.Error(w, "unable to get user info", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-type", "application/json")
		fmt.Fprint(w, string(userInfo))
	}
}

func getGitHubUserInfo(accessToken string) ([]byte, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		"https://api.github.com/user",
		http.NoBody,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
