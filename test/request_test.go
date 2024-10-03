package test

import (
	"log"
	"os"
	"testing"

	"github.com/nharu-0630/gakujo-zero-api/cmd"
	"github.com/nharu-0630/gakujo-zero-api/tools"
)

var testCmd *cmd.Cmd

func TestMain(m *testing.M) {
	tools.LoadEnv()
	username := os.Getenv("GAKUJO_USERNAME")
	password := os.Getenv("GAKUJO_PASSWORD")
	secret := os.Getenv("GAKUJO_SECRET")

	var err error
	testCmd, err = cmd.NewClient()
	if err != nil {
		log.Fatalf("Failed to create new client: %v", err)
	}

	err = testCmd.Login(username, password, secret)
	if err != nil {
		log.Fatalf("Failed to login: %v", err)
	}

	ret := m.Run()
	os.Exit(ret)
}

func TestUserInformation(t *testing.T) {
	userInformation, err := testCmd.GetUserInformation()
	if err != nil {
		t.Error(err)
		return
	}
	log.Default().Println("Successfully got user information")
	log.Default().Println(userInformation)
}

func TestImportantNotice(t *testing.T) {
	importantNotice, err := testCmd.GetImportantNotice()
	if err != nil {
		t.Error(err)
		return
	}
	log.Default().Println("Successfully got important notice")
	log.Default().Println(importantNotice)
}

func TestWarningNoticeInformation(t *testing.T) {
	warningNoticeInformation, err := testCmd.GetWarningNoticeInformation()
	if err != nil {
		t.Error(err)
		return
	}
	log.Default().Println("Successfully got warning notice information")
	log.Default().Println(warningNoticeInformation)
}

func TestSubmissionInformation(t *testing.T) {
	submissionInformation, err := testCmd.GetSubmissionInformation()
	if err != nil {
		t.Error(err)
		return
	}
	log.Default().Println("Successfully got submission information")
	log.Default().Println(submissionInformation)
}
