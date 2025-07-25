package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Runninginsilence1/scanner/internal/ping"
)

// ping 网络连接

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "扫描局域网内的ping服务",
	Long:  `扫描局域网内的ping服务, 检测主机是否存活`,
	Run: func(cmd *cobra.Command, args []string) {
		if OutputFormat == "default" {
			SSHPrint()
		}
		ping.Parallel(Prefix, Start, End, OutputFormat)
	},
}
