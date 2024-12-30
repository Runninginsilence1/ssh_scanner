package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Runninginsilence1/scanner/internal/dumper"
)

// print options
var (
	NetworkFailed        bool
	AuthenticationFailed bool
)

// args for rootCmd
var (
	Prefix   int    // 网段
	Start    int    // 起始IP
	End      int    // 结束IP
	User     string // 用户名
	Password string // 密码
)

// arg for output format
var (
	OutputFormat string
	_            struct{}
)

var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "扫描局域网内的SSH服务并尝试密码或密钥登录",
	Long:  `扫描局域网内的SSH服务并尝试密码或密钥登录`,
	Run: func(cmd *cobra.Command, _ []string) {
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {

	// PersistentFlags: 全局参数, 所有子命令都可以使用
	// Flags: 局部参数, 只能在当前命令中使用
	{
		rootCmd.PersistentFlags().IntVarP(&Prefix, "prefix", "p", 3, "网段, 例如 3")
		rootCmd.PersistentFlags().IntVarP(&Start, "start", "s", 1, "起始IP的最后一位, 例如 1")
		rootCmd.PersistentFlags().IntVarP(&End, "end", "e", 254, "结束IP的最后一位, 例如 254")
		rootCmd.PersistentFlags().StringVarP(&User, "user", "u", "root", "用户名, 例如 root")
		rootCmd.PersistentFlags().StringVarP(&Password, "password", "P", "123456", "密码, 例如 123456")
		rootCmd.PersistentFlags().StringVarP(&OutputFormat, "output-format", "", "console", "输出格式, 可选:"+dumper.GetAllTypeString())

		rootCmd.Flags().BoolVarP(&NetworkFailed, "network", "n", false, "是否显示因为网络错误而失败的IP")
		rootCmd.Flags().BoolVarP(&AuthenticationFailed, "auth", "a", false, "是否显示因为认证错误而失败的IP")
		rootCmd.Flags().BoolVarP(&EnablePubKey, "pubkey", "", false, "是否启用公钥登录")
	}

	{
		sshCmd.Flags().BoolVarP(&EnablePubKey, "pubkey", "", false, "是否启用公钥登录")
	}

	{
		rootCmd.AddCommand(sshCmd)
		rootCmd.AddCommand(pingCmd)
	}
}

func Execute() error {
	return rootCmd.Execute()
}

func Print() {
	// ip地址范围:
	// 使用用户名
	// 密码

	fmt.Printf("扫描范围: 192.168.%d.%d 到 192.168.%d.%d\n", Prefix, Start, Prefix, End)
	fmt.Printf("登录用户名: %s\n", User)
	fmt.Printf("登录密码: %s\n", Password)
	if EnablePubKey {
		fmt.Println("启用公钥登录")
	}
	fmt.Println()
	//fmt.Println("IP List:")
}
