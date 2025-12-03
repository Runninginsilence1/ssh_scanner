package main

import (
	"fmt"
	"log"

	"github.com/Runninginsilence1/scanner/cmd"
	"github.com/Runninginsilence1/scanner/internal/globalcontext"
)

func main() {
	log.SetFlags(log.Lshortfile)

	// 监听全局 context 取消（由 globalcontext 包中的信号处理触发）
	go func() {
		<-globalcontext.Ctx.Done()
		fmt.Println("\n收到中断信号，正在优雅退出...")
	}()

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
