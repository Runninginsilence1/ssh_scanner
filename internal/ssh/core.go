package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/formatter"
	"github.com/duke-git/lancet/v2/slice"
	"golang.org/x/crypto/ssh"

	"github.com/Runninginsilence1/scanner/internal/dumper"
	"github.com/Runninginsilence1/scanner/internal/ip_gen"
	"github.com/Runninginsilence1/scanner/pkg/ip_helper"
)

// 错误类型
var (
	NetworkError = errors.New("NetworkError")
	AuthError    = errors.New("AuthError")
)

// 验证初始化
var (
	readPubKeyFileOnce sync.Once
	authMethod         ssh.AuthMethod
)

type Result struct {
	OkList         []string `json:"ok_list"`
	AuthErrList    []string `json:"auth_err_list"`
	NetworkErrList []string `json:"network_err_list"`
}

func TryConnectServerV2(ctx context.Context, ipPort string, password string, user string, enablePubKey bool) (err error) {
	method := []ssh.AuthMethod{
		//addIdRsaFileAuth(),
		ssh.Password(password),
	}

	if enablePubKey {
		method = append(method, addIdRsaFileAuth())
	}

	// 设置客户端请求参数

	config := &ssh.ClientConfig{
		User: user,
		// 支持公钥认证和密码验证
		Auth: method,
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 忽略主机密钥不匹配的情况

		Timeout: 500 * time.Millisecond, // 这个 timeout 只影响握手阶段的判断，
	}

	// 作为客户端连接SSH服务器
	// 使用 goroutine 和 select 实现 context 取消功能

	type dialResult struct {
		client *ssh.Client
		err    error
	}
	resultCh := make(chan dialResult, 1)

	go func() {
		client, err := ssh.Dial("tcp", ipPort, config)
		resultCh <- dialResult{client, err}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			var errOp *net.OpError
			if errors.As(result.err, &errOp) {
				err = NetworkError
			} else {
				err = AuthError
			}
			return err
		}
		defer result.client.Close()
		return nil
	}
}

func addIdRsaFileAuth() ssh.AuthMethod {
	//C:\Users\H\.ssh\known_hosts

	// 使用 once 保证只读取一次公钥文件, 提高性能

	readPubKeyFileOnce.Do(func() {
		knownHostspath := `C:\Users\H\.ssh\id_rsa`
		reader, _, err := fileutil.ReadFile(knownHostspath)
		if err != nil {
			log.Fatal(err)
		}
		pubKeyBytes, err := io.ReadAll(reader)

		// 解析id_rsa文件

		privateKey, err := ssh.ParsePrivateKey(pubKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		// 创建 AuthMethod
		authMethod = ssh.PublicKeys(privateKey)
	})

	return authMethod
}

type Option struct {
	ShowNetwork  bool
	ShowAuth     bool
	ShowOk       bool
	EnablePubKey bool
	Verbose      bool
	Loop         bool
	MaxWorkers   int // 最大并发数，默认 500
}

func ScannerV2(ctx context.Context, prefix, start, end int, user, password string, opt Option, format string) {
	dumpType, err := dumper.GetType(format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	calTime := time.Now()
	defer func() {
		fmt.Printf("扫描完成, 用时: %v ms\n", time.Since(calTime).Milliseconds())
	}()

	// 设置默认并发数
	maxWorkers := opt.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = 500
	}

	// 创建带缓冲的结果 channel
	var (
		okChan      = make(chan string, 100)
		authChan    = make(chan string, 100)
		networkChan = make(chan string, 100)
		doneChan    = make(chan struct{})
	)

	var (
		okArr      []string
		authArr    []string
		networkArr []string
	)

	// 启动结果收集 goroutine
	go func() {
		defer close(doneChan)
		for {
			select {
			case ip, ok := <-okChan:
				if !ok {
					okChan = nil
				} else {
					okArr = append(okArr, ip)
				}
			case ip, ok := <-authChan:
				if !ok {
					authChan = nil
				} else {
					authArr = append(authArr, ip)
				}
			case ip, ok := <-networkChan:
				if !ok {
					networkChan = nil
				} else {
					networkArr = append(networkArr, ip)
				}
			}
			// 当所有 channel 都关闭时退出
			if okChan == nil && authChan == nil && networkChan == nil {
				return
			}
		}
	}()

	// 创建任务队列
	taskCh := make(chan int, 100)
	var wg sync.WaitGroup

	// 启动 worker pool
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for suffix := range taskCh {
				// 检查 context 是否已取消
				select {
				case <-ctx.Done():
					return
				default:
				}

				ipAddr := ip_gen.GetSshAddr(prefix, suffix)
				if opt.Loop {
					loopMode(ctx, ipAddr, password, user, opt)
					continue
				}

				err := TryConnectServerV2(ctx, ipAddr, password, user, opt.EnablePubKey)
				if err == nil {
					if opt.Verbose {
						fmt.Printf("%v\tok\n", ipAddr)
					}
					okChan <- ipAddr
				} else if errors.Is(err, AuthError) {
					if opt.Verbose && opt.ShowAuth {
						fmt.Printf("%v\tauth error\n", ipAddr)
					}
					authChan <- ipAddr
				} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					// context 取消，不记录错误
					return
				} else {
					if opt.Verbose && opt.ShowNetwork {
						fmt.Printf("%v\tnetwork error\n", ipAddr)
					}
					networkChan <- ipAddr
				}
			}
		}()
	}

	// 发送任务到任务队列
	go func() {
		for i := start; i <= end; i++ {
			select {
			case <-ctx.Done():
				break
			case taskCh <- i:
			}
		}
		close(taskCh)
	}()

	// 等待所有 worker 完成
	wg.Wait()

	// 关闭结果 channel
	close(okChan)
	close(authChan)
	close(networkChan)

	// 等待结果收集完成
	<-doneChan

	sortByIpLast(okArr)
	sortByIpLast(authArr)
	sortByIpLast(networkArr)

	output(okArr, authArr, networkArr, opt, dumpType)
}

// 如果是loop模式则忽略 channel 以及 verbose 标志直接显示
// 成功则退出循环
func loopMode(ctx context.Context, ipAddr string, password string, user string, opt Option) {
	for {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := TryConnectServerV2(ctx, ipAddr, password, user, opt.EnablePubKey)
		if err == nil {
			fmt.Printf("%v\tok\n", ipAddr)
			return
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// context 取消，退出循环
			return
		} else if errors.Is(err, AuthError) {
			if opt.ShowAuth {
				fmt.Printf("%v\tauth error\n", ipAddr)
			}
		} else {
			if opt.ShowNetwork {
				fmt.Printf("%v\tnetwork error\n", ipAddr)
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func sortByIpLast(ips []string) {
	slice.SortBy(ips, func(a, b string) bool {
		a = strings.TrimSuffix(a, ":22")
		b = strings.TrimSuffix(b, ":22")

		i := ip_helper.GetIpLast(a)
		j := ip_helper.GetIpLast(b)

		return i < j
	})
}

func output(okArr, authArr, networkArr []string, opt Option, dumpType dumper.Type) {
	switch dumpType {
	case dumper.Console:
		if opt.ShowAuth {
			fmt.Println("认证失败:")
			for _, ip := range authArr {
				fmt.Println(ip)
			}
			fmt.Println()
		}
		if opt.ShowNetwork {
			fmt.Println("网络错误:")
			for _, ip := range networkArr {
				fmt.Println(ip)
			}
			fmt.Println()
		}

		//if opt.ShowOk {
		if true {
			if len(okArr) > 0 {
				fmt.Println("成功登录:")
				for _, ip := range okArr {
					fmt.Println(ip)
				}
			} else {
				fmt.Println("没有成功登录的主机")
			}
		}
	case dumper.JSON:
		result := Result{}

		result.OkList = okArr

		if opt.ShowNetwork {
			result.NetworkErrList = networkArr
		}

		if opt.ShowAuth {
			result.AuthErrList = authArr
		}

		pretty, _ := formatter.Pretty(result)
		fmt.Println(pretty)
	}
}
