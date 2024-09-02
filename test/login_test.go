package test

import (
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

	c := cmd.NewClient()
	err := c.Login(username, password, secret)
	if err != nil {
		t.Error(err)
	}
	t.Log("Login successful")
}
