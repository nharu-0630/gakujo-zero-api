package test

import (
	"log"
	"os"
	"testing"

	"github.com/nharu-0630/gakujo-zero-api/cmd"
	"github.com/nharu-0630/gakujo-zero-api/tools"
)

func TestLogin(t *testing.T) {
	tools.LoadEnv()
	username := os.Getenv("GAKUJO_USERNAME")
	password := os.Getenv("GAKUJO_PASSWORD")
	secret := os.Getenv("GAKUJO_SECRET")

	cmd, err := cmd.NewClient()
	if err != nil {
		t.Error(err)
		return
	}
	err = cmd.Login(username, password, secret)
	if err != nil {
		t.Error(err)
		return
	}
	log.Default().Println("Successfully logged in")

	userInformation, err := cmd.GetUserInformation()
	if err != nil {
		t.Error(err)
		return
	}
	log.Default().Println(userInformation)

	importantNotice, err := cmd.GetImportantNotice()
	if err != nil {
		t.Error(err)
		return
	}
	log.Default().Println(importantNotice)
}
