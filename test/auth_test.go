package test

import (
	"os"
	"testing"

	"github.com/nharu-0630/gakujo-zero-api/cmd"
	"github.com/nharu-0630/gakujo-zero-api/tools"
)

func TestAuthentication(t *testing.T) {
	tools.LoadEnv()
	username := os.Getenv("GAKUJO_USERNAME")
	password := os.Getenv("GAKUJO_PASSWORD")
	secret := os.Getenv("GAKUJO_SECRET")

	c := cmd.NewClient()
	as := cmd.NewAuthSession(*c, username, password, secret)
	err := as.Auth()
	if err != nil {
		panic(err)
	}
}
