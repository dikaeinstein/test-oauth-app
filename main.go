package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/dghubble/gologin/v2"
	"github.com/dghubble/gologin/v2/github"
	"golang.org/x/oauth2"
	oauth2github "golang.org/x/oauth2/github"
)

const addr = "localhost:8080"

func main() {
	githubClientID := os.Getenv("GITHUB_CLIENT_ID")
	githubClientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	if githubClientID == "" || githubClientSecret == "" {
		slog.Error("Set GITHUB_CLIENT_* env vars")
		os.Exit(1)
	}

	conf := oauth2.Config{
		ClientID:     githubClientID,
		ClientSecret: githubClientSecret,
		Endpoint:     oauth2github.Endpoint,
	}

	cookieConf := gologin.DebugOnlyCookieConfig
	loginHandler := github.LoginHandler(&conf, nil)
	callbackHandler := github.CallbackHandler(&conf, http.HandlerFunc(githubCallbackHandler), nil)

	http.HandleFunc("/", rootHandler)
	http.Handle("/login", github.StateHandler(cookieConf, loginHandler))
	http.Handle("/github/callback", github.StateHandler(cookieConf, callbackHandler))

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

func githubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	githubUser, err := github.UserFromContext(r.Context())
	if err != nil {
		slog.Error("unable to get GitHub user", slog.String("err", err.Error()))
		http.Error(w, "unable to get GitHub user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	buf, err := json.Marshal(githubUser)
	if err != nil {
		http.Error(w, "unable to marshal GitHub user", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, string(buf))
}
