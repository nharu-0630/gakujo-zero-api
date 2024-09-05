package main

import (
	"os"

	"github.com/nharu-0630/gakujo-zero-api/cmd"
	"github.com/nharu-0630/gakujo-zero-api/tools"
)

func main() {
	tools.LoadEnv()
	username := os.Getenv("GAKUJO_USERNAME")
	password := os.Getenv("GAKUJO_PASSWORD")
	secret := os.Getenv("GAKUJO_SECRET")

	cmd, err := cmd.NewClient()
	if err != nil {
		panic(err)
	}
	err = cmd.Login(username, password, secret)
	if err != nil {
		panic(err)
	}
}
