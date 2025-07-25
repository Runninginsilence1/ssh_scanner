package cmd

import (
	"fmt"

	"github.com/Runninginsilence1/scanner/internal/detect"
	"github.com/spf13/cobra"
)

var (
	EnableUUID = false
	UUIDStr    = ""
	Port       int
)

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "扫描局域网内的自定义服务",
	Long:  `用Go写了一个客户端程序，通过指定UUID环境变量和端口来查询局域网内的自定义服务。`,
	Run: func(cmd *cobra.Command, args []string) {
		option := detect.Option{
			EnableUUID: EnableUUID,
			UUIDStr:    UUIDStr,
			Port:       Port,
		}
		fmt.Println("Option参数", option)
		detect.Scanner(Prefix, Start, End, option)
	},
}
