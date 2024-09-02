package cmd

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
)

type Cmd struct {
	client *http.Client
}

func NewClient() *Cmd {
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	return &Cmd{
		client: &http.Client{
			Jar: jar,
		},
	}
}

func extractCSRFToken(resp *http.Response) (string, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	re := regexp.MustCompile(`<input type="hidden" name="(?:_csrf|csrf_token)" value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", errors.New("CSRF token not found")
}
