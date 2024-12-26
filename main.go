package main

import (
	"log"

	"github.com/Runninginsilence1/scanner/cmd"
)

// 用 cobra

// TODO: 更加合适的接收参数的方式; pflag 或者 viper

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
