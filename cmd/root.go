package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"ssh_scanner/internal/core"
)

// args for rootCmd

var Prefix int      // 网段
var Start int       // 起始IP
var End int         // 结束IP
var User string     // 用户名
var Password string // 密码
// prefix, start, end int, user, password string

// concept of Command
var rootCmd = &cobra.Command{
	Use:   "ssh_scanner",
	Short: "扫描局域网内的SSH服务并尝试密码登录",
	Long:  `扫描局域网内的SSH服务并尝试密码登录`,
	Run: func(cmd *cobra.Command, args []string) {
		Print()
		//ssh_demo.SSHScanner(Prefix, Start, End, User, Password)
		core.SSHScannerV2(Prefix, Start, End, User, Password)
	},
}

func init() {
	{
		rootCmd.Flags().IntVarP(&Prefix, "prefix", "p", 3, "网段, 例如 3")
		rootCmd.Flags().IntVarP(&Start, "start", "s", 1, "起始IP的最后一位, 例如 1")
		rootCmd.Flags().IntVarP(&End, "end", "e", 254, "结束IP的最后一位, 例如 254")
		rootCmd.Flags().StringVarP(&User, "user", "u", "root", "用户名, 例如 root")
		rootCmd.Flags().StringVarP(&Password, "password", "P", "123456", "密码, 例如 123456")
	}
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		return err
	}
	return nil
}

func Print() {
	// ip地址范围:
	// 使用用户名
	// 密码

	fmt.Printf("From 192.168.%d.%d to 192.168.%d.%d\n", Prefix, Start, Prefix, End)
	fmt.Printf("User: %s\n", User)
	fmt.Printf("Password: %s\n", Password)
	fmt.Println()
	fmt.Println("IP List:")
}
