package model

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type UserInformation struct {
	UserName               string      `json:"userName"`
	LastUpdateTime         string      `json:"lastUpdateTime"`
	BookmarkImageKey       interface{} `json:"bookmarkImageKey"`
	BookmarkImage          string      `json:"bookmarkImage"`
	BookmarkImageExtension string      `json:"bookmarkImageExtension"`
}

func GetUserInformation(resp *http.Response) (*UserInformation, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	var userInformation UserInformation
	if err := json.NewDecoder(resp.Body).Decode(&userInformation); err != nil {
		return nil, err
	}
	return &userInformation, nil
}
