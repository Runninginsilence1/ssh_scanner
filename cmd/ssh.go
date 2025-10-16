package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Runninginsilence1/scanner/internal/ssh"
)

// ssh命令

var (
	EnablePubKey bool
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "扫描局域网内的SSH服务并尝试密码或密钥登录",
	Long:  `扫描局域网内的SSH服务并尝试密码或密钥登录`,
	Run: func(cmd *cobra.Command, args []string) {
		if OutputFormat == "default" {
			SSHPrint()
		}
		option := ssh.Option{
			ShowAuth:     AuthenticationFailed,
			ShowNetwork:  NetworkFailed,
			EnablePubKey: EnablePubKey,
			Verbose:      Verbose,
			Loop:         Loop,
		}
		ssh.ScannerV2(Prefix, Start, End, User, Password, option, OutputFormat)
	},
}
