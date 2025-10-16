package ssh

import (
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

func TryConnectServerV2(ipPort string, password string, user string, enablePubKey bool) (err error) {
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

	// 统计超时时间
	//startTime := time.Now()
	//defer func() {
	//	elapsed := time.Since(startTime)
	//	fmt.Printf("TryConnectServerV2: %v: ssh.Dial 执行耗时: %vms\n", ipPort, elapsed.Milliseconds())
	//}()
	client, err := ssh.Dial("tcp", ipPort, config)
	if err != nil {
		var errOp *net.OpError
		if errors.As(err, &errOp) {
			err = NetworkError
		} else {
			err = AuthError
		}
		return
	}
	defer client.Close()
	return nil
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
}

func ScannerV2(prefix, start, end int, user, password string, opt Option, format string) {
	dumpType, err := dumper.GetType(format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	calTime := time.Now()
	defer func() {
		fmt.Printf("扫描完成, 用时: %v ms\n", time.Now().Sub(calTime).Milliseconds())
	}()
	// 构建队列和启动并发
	// 完成go前需要设置done
	var wg sync.WaitGroup
	taskNum := end - start + 1
	wg.Add(taskNum)

	var (
		// 另外用一个goroutine来接收结果
		okChan      = make(chan string)
		authChan    = make(chan string)
		networkChan = make(chan string)
		doneChan    = make(chan struct{})
	)

	var (
		okArr      []string
		authArr    []string
		networkArr []string
	)

	go func() {
		for {
			select {
			case ip := <-okChan:
				okArr = append(okArr, ip)
			case ip := <-authChan:
				authArr = append(authArr, ip)
			case ip := <-networkChan:
				networkArr = append(networkArr, ip)
			case <-doneChan:
				return
			}
		}
	}()

	for i := start; i <= end; i++ {
		go func(suffix int) {
			defer wg.Done()
			ipAddr := ip_gen.GetSshAddr(prefix, suffix)
			if opt.Loop {
				loopMode(ipAddr, password, user, opt)
				return
			}

			err := TryConnectServerV2(ipAddr, password, user, opt.EnablePubKey)
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
			} else {
				if opt.Verbose && opt.ShowNetwork {
					fmt.Printf("%v\tnetwork error\n", ipAddr)
				}
				networkChan <- ipAddr
			}
		}(i)
	}
	wg.Wait()
	close(doneChan)

	sortByIpLast(okArr)
	sortByIpLast(authArr)
	sortByIpLast(networkArr)

	//output(okList, dumpType)

	output(okArr, authArr, networkArr, opt, dumpType)
}

// 如果是loop模式则忽略 channel 以及 verbose 标志直接显示
// 成功则退出循环
func loopMode(ipAddr string, password string, user string, opt Option) {
	for {
		err := TryConnectServerV2(ipAddr, password, user, opt.EnablePubKey)
		if err == nil {
			fmt.Printf("%v\tok\n", ipAddr)
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
