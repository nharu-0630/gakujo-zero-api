package cmd

import (
	"github.com/nharu-0630/gakujo-zero-api/configs"
	"github.com/nharu-0630/gakujo-zero-api/model"
)

func (c *Cmd) GetUserInformation() (*model.UserInformation, error) {
	headers := map[string]string{
		"User-Agent":         configs.USER_AGENT,
		"Accept":             "application/json, text/javascript, */*; q=0.01",
		"Accept-Language":    "ja",
		"Connection":         "keep-alive",
		"Referer":            "https://gakujo.shizuoka.ac.jp/lcu-web/SC_01002B00_00",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-origin",
		"X-CSRF-TOKEN":       c.csrf,
		"X-Requested-With":   "XMLHttpRequest",
		"sec-ch-ua":          `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
	}
	resp, err := c.request("GET", "https://gakujo.shizuoka.ac.jp/lcu-web/SC_01002B00_00/userInformation", nil, headers)
	if err != nil {
		return nil, err
	}
	return model.GetUserInformation(resp)
}

func (c *Cmd) GetImportantNotice() (*model.ImportantNotice, error) {
	headers := map[string]string{
		"User-Agent":         configs.USER_AGENT,
		"Accept":             "application/json, text/javascript, */*; q=0.01",
		"Accept-Language":    "ja",
		"Connection":         "keep-alive",
		"Referer":            "https://gakujo.shizuoka.ac.jp/lcu-web/SC_01002B00_00",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-origin",
		"X-CSRF-TOKEN":       c.csrf,
		"X-Requested-With":   "XMLHttpRequest",
		"sec-ch-ua":          `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
	}
	resp, err := c.request("GET", "https://gakujo.shizuoka.ac.jp/lcu-web/SC_01002B00_00/importantNotice", nil, headers)
	if err != nil {
		return nil, err
	}
	return model.GetImportantNotice(resp)
}

func (c *Cmd) GetWarningNoticeInformation() (*model.WarningNoticeInformation, error) {
	headers := map[string]string{
		"User-Agent":         configs.USER_AGENT,
		"Accept":             "application/json, text/javascript, */*; q=0.01",
		"Accept-Language":    "ja",
		"Connection":         "keep-alive",
		"Referer":            "https://gakujo.shizuoka.ac.jp/lcu-web/SC_01002B00_00",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-origin",
		"X-CSRF-TOKEN":       c.csrf,
		"X-Requested-With":   "XMLHttpRequest",
		"sec-ch-ua":          `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
	}
	resp, err := c.request("GET", "https://gakujo.shizuoka.ac.jp/lcu-web/SC_01002B00_01/warningNoticeInformation", nil, headers)
	if err != nil {
		return nil, err
	}
	return model.GetWarningNoticeInformation(resp)
}
