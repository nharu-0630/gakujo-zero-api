package model

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type ImportantNotice []struct {
	ContactSeq                   string `json:"contactSeq"`
	ContactDate                  string `json:"contactDate"`
	ContactTime                  string `json:"contactTime"`
	ContactTypeCode              string `json:"contactTypeCode"`
	ContactTypeTitle             string `json:"contactTypeTitle"`
	Title                        string `json:"title"`
	ImportanceCategory           string `json:"importanceCategory"`
	TargetDate                   string `json:"targetDate"`
	SubjectClassSemesterWeekHour string `json:"subjectClassSemesterWeekHour"`
}

func GetImportantNotice(resp *http.Response) (*ImportantNotice, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	var importantNotice ImportantNotice
	if err := json.NewDecoder(resp.Body).Decode(&importantNotice); err != nil {
		return nil, err
	}
	return &importantNotice, nil
}
