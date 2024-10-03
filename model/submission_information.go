package model

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type SubmissionInformation []struct {
	SubmissionSeq                    string      `json:"submissionSeq"`
	SubmissionSeqOrID                string      `json:"submissionSeqOrId"`
	SubmissionTypeCode               string      `json:"submissionTypeCode"`
	SubmissionType                   string      `json:"submissionType"`
	SubmissionTitle                  string      `json:"submissionTitle"`
	SubmitTermEndDatetime            string      `json:"submitTermEndDatetime"`
	Until                            interface{} `json:"until"`
	DatetimeAndTo                    string      `json:"datetimeAndTo"`
	SubmitStatus                     string      `json:"submitStatus"`
	SubmitCount                      interface{} `json:"submitCount"`
	SubmitTargetCount                interface{} `json:"submitTargetCount"`
	SubmitRateAndCountPerTargetCount interface{} `json:"submitRateAndCountPerTargetCount"`
	StudentNumber                    string      `json:"studentNumber"`
	StaffNumber                      interface{} `json:"staffNumber"`
	SubmissionRequestPath            string      `json:"submissionRequestPath"`
	NoContentData                    interface{} `json:"noContentData"`
	Year                             string      `json:"year"`
	SubjectCode                      string      `json:"subjectCode"`
	ClassCode                        string      `json:"classCode"`
	SubjectName                      string      `json:"subjectName"`
	ClassName                        string      `json:"className"`
	BeginSemesterCode                interface{} `json:"beginSemesterCode"`
	InternalOperationDivision        interface{} `json:"internalOperationDivision"`
	ExternalOperationDivision        interface{} `json:"externalOperationDivision"`
}

func GetSubmissionInformation(resp *http.Response) (*SubmissionInformation, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	var submissionInformation SubmissionInformation
	if err := json.NewDecoder(resp.Body).Decode(&submissionInformation); err != nil {
		return nil, err
	}
	return &submissionInformation, nil
}
