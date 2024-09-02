package model

import (
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type Home struct {
	UserName      string    `json:"userName"`
	UserLastLogin time.Time `json:"userLastLogin"`
	Notice        []struct {
		Date     time.Time `json:"date"`
		Category string    `json:"category"`
		Title    string    `json:"title"`
	} `json:"notice"`
}

func NewHome(resp *http.Response) (Home, error) {
	home := new(Home)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return Home{}, err
	}
	home.UserName = doc.Find("#userInfomation > div.index-main-visual-user-information > div.index-main-visual-user-name").Text()
	home.UserLastLogin, err = time.Parse("2006-01-02 15:04", strings.Split(doc.Find("#userInfomation > div.index-main-visual-user-information > div.index-main-visual-user-last-login").Text(), "：")[1])
	if err != nil {
		return Home{}, err
	}
	return *home, nil
}
