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

	Loop bool
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
	Verbose      bool
	_            struct{}
)

var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "多功能扫描器",
	Long:  `多功能扫描器, 支持SSH扫描, 端口扫描, 网络扫描(仅tcp).`,
	Run: func(cmd *cobra.Command, _ []string) {
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {

	// PersistentFlags: 全局参数, 所有子命令都可以使用
	// Flags: 局部参数, 只能在当前命令中使用
	{
		rootCmd.PersistentFlags().
			IntVarP(&Prefix, "prefix", "p", 3, "网段, 例如 3")
		rootCmd.PersistentFlags().
			IntVarP(&Start, "start", "s", 1, "起始IP的最后一位, 例如 1")
		rootCmd.PersistentFlags().
			IntVarP(&End, "end", "e", 254, "结束IP的最后一位, 例如 254")
		rootCmd.PersistentFlags().
			StringVarP(&OutputFormat, "output-format", "", "console", "输出格式, 可选:"+dumper.GetAllTypeString())
		rootCmd.PersistentFlags().
			BoolVarP(&Verbose, "verbose", "v", false, "显示详细信息")
	}

	{
		sshCmd.PersistentFlags().
			StringVarP(&User, "user", "u", "root", "用户名, 例如 root")
		sshCmd.PersistentFlags().
			StringVarP(&Password, "password", "P", "123456", "密码, 例如 123456")
		sshCmd.Flags().
			BoolVarP(&NetworkFailed, "network", "n", false, "是否显示因为网络错误而失败的IP")
		sshCmd.Flags().
			BoolVarP(&AuthenticationFailed, "auth", "a", false, "是否显示因为认证错误而失败的IP")
		sshCmd.Flags().
			BoolVarP(&EnablePubKey, "pubkey", "", false, "是否启用公钥登录")
		sshCmd.Flags().BoolVarP(&Loop, "loop", "l", false, "是否启用循环检索模式")
	}

	// detectCmd的参数
	{
		detectCmd.Flags().
			BoolVarP(&EnableUUID, "enable-uuid", "", false, "是否验证UUID")
		detectCmd.Flags().
			StringVarP(&UUIDStr, "uuid", "", "481fe328-4a38-4eac-8189-0cee06846d4a", "UUID字符串")
		detectCmd.Flags().
			IntVarP(&Port, "port", "", 8080, "自定义服务端的端口，默认8080")
	}

	{
		rootCmd.AddCommand(sshCmd)
		rootCmd.AddCommand(pingCmd)
		rootCmd.AddCommand(detectCmd)
	}
}

func Execute() error {
	return rootCmd.Execute()
}

func SSHPrint() {
	fmt.Printf(
		"扫描范围: 192.168.%d.%d 到 192.168.%d.%d\n",
		Prefix,
		Start,
		Prefix,
		End,
	)
	fmt.Printf("登录用户名: %s\n", User)
	fmt.Printf("登录密码: %s\n", Password)
	if EnablePubKey {
		fmt.Println("启用公钥登录")
	}
	fmt.Println()
	//fmt.Println("IP List:")
}
