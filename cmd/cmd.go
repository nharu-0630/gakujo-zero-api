package cmd

import (
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.nhat.io/cookiejar"
)

type Cmd struct {
	client *http.Client
	csrf   string
}

func NewClient() (*Cmd, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cacheDir := filepath.Join(homeDir, ".cache", ".gakujo-zero-api")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}
	log.Default().Println("Cache directory:", cacheDir)
	cachePath := filepath.Join(cacheDir, "cookies.json")
	if _, err := os.Stat(cachePath); err == nil {
		log.Default().Println("Cache file exists:", cachePath)
	} else if os.IsNotExist(err) {
		log.Default().Println("Cache file does not exist, will be created:", cachePath)
	} else {
		return nil, err
	}
	jar := cookiejar.NewPersistentJar(
		cookiejar.WithFilePath(cachePath),
		cookiejar.WithFilePerm(0755),
		cookiejar.WithAutoSync(true),
	)
	return &Cmd{
		client: &http.Client{
			Jar: jar,
		},
	}, nil
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
	return "", errors.New("failed to extract CSRF token")
}

func extractConfig(resp *http.Response) (map[string]string, error) {
	re := regexp.MustCompile(`Config={(.*?)};`)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return nil, errors.New("failed to extract config")
	}
	configStr := matches[1]
	config := make(map[string]string)
	for _, line := range strings.Split(configStr, ",") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.Trim(parts[0], `"`+"`")
		value := strings.Trim(parts[1], `"`+"`")
		config[key] = value
	}
	return config, nil
}

func (cmd *Cmd) request(method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	if body == nil {
		body = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := cmd.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	return resp, nil
}
