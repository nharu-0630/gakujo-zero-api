package model

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type WarningNoticeInformation []struct {
	WarningNoticeSize                     string        `json:"warningNoticeSize"`
	WarningNoticeID                       string        `json:"warningNoticeId"`
	WarningNoticeName                     string        `json:"warningNoticeName"`
	WarningNoticeRequestPath              string        `json:"warningNoticeRequestPath"`
	WarningNoticeDateExistence            string        `json:"warningNoticeDateExistence"`
	WarningNoticeCountExistence           string        `json:"warningNoticeCountExistence"`
	WarningNoticeStatusExistence          string        `json:"warningNoticeStatusExistence"`
	WarningNoticeContent                  string        `json:"warningNoticeContent"`
	WarningNoticeContentMonth             string        `json:"warningNoticeContentMonth"`
	WarningNoticeContentMonthText         string        `json:"warningNoticeContentMonthText"`
	WarningNoticeContentHalfSizeSlash     interface{}   `json:"warningNoticeContentHalfSizeSlash"`
	WarningNoticeContentHalfSizeSlashText interface{}   `json:"warningNoticeContentHalfSizeSlashText"`
	WarningNoticeContentDay               string        `json:"warningNoticeContentDay"`
	WarningNoticeContentDayText           string        `json:"warningNoticeContentDayText"`
	WarningNoticeContentCount             string        `json:"warningNoticeContentCount"`
	WarningNoticeContentCountText         string        `json:"warningNoticeContentCountText"`
	WarningNoticeStatusID                 string        `json:"warningNoticeStatusId"`
	WarningNoticeStatusName               string        `json:"warningNoticeStatusName"`
	StudyResultShortenedDisplayCount      interface{}   `json:"studyResultShortenedDisplayCount"`
	ChartShortenedDisplayCount            interface{}   `json:"chartShortenedDisplayCount"`
	WarningNoticeInformationDateList      []interface{} `json:"warningNoticeInformationDateList"`
	WarningDisplayExamType                interface{}   `json:"warningDisplayExamType"`
}

func GetWarningNoticeInformation(resp *http.Response) (*WarningNoticeInformation, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	var warningNoticeInformation WarningNoticeInformation
	if err := json.NewDecoder(resp.Body).Decode(&warningNoticeInformation); err != nil {
		return nil, err
	}
	return &warningNoticeInformation, nil
}
