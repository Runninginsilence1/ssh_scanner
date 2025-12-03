package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Runninginsilence1/scanner/internal/globalcontext"
	"github.com/Runninginsilence1/scanner/internal/ssh"
)

// ssh命令

var (
	EnablePubKey bool
	SSHPort      int
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "扫描局域网内的SSH服务并尝试密码或密钥登录",
	Long:  `扫描局域网内的SSH服务并尝试密码或密钥登录`,
	Run: func(cmd *cobra.Command, args []string) {
		option := ssh.Option{
			ShowAuth:     AuthenticationFailed,
			ShowNetwork:  NetworkFailed,
			EnablePubKey: EnablePubKey,
			Verbose:      Verbose,
			Loop:         Loop,
			MaxWorkers:   0, // 使用默认值 500
			Port:         SSHPort,
		}

		// 如果是 console 输出格式且不是 verbose 模式，使用 bubbletea
		if OutputFormat == "console" && !Verbose {
			SSHPrint()
			ssh.ScannerWithTea(globalcontext.Ctx, Prefix, Start, End, User, Password, option, OutputFormat)
		} else {
			// 其他情况使用原来的扫描器
			if OutputFormat == "default" {
				SSHPrint()
			}
			ssh.ScannerV2(globalcontext.Ctx, Prefix, Start, End, User, Password, option, OutputFormat)
		}
	},
}
