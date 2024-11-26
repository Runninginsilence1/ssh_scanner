package core

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/duke-git/lancet/v2/fileutil"
	"golang.org/x/crypto/ssh"
)

var (
	NetworkError = errors.New("NetworkError")
	AuthError    = errors.New("AuthError")
)

//type NetworkError struct {
//	Err error
//}
//
//func (e *NetworkError) Error() string {
//	return fmt.Sprintf("NetworkError: %v", e.Err)
//}
//
//type AuthError struct {
//	Err error
//}
//
//func (e *AuthError) Error() string {
//	return fmt.Sprintf("NetworkError: %v", e.Err)
//}

// TryConnectServer provides ssh client login by password or key auth.
// Example: TryConnectServer("192.168.6.61:22", "123456", "root")
// 实际连接的参数
func TryConnectServer(ipPort string, password string, user string) (ok bool) {
	// 设置客户端请求参数
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			addIdRsaFileAuth(),
			ssh.Password(password),
		},
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 忽略主机密钥
		Timeout:         1000 * time.Millisecond,
	}

	// 作为客户端连接SSH服务器
	client, err := ssh.Dial("tcp", ipPort, config)
	if err != nil {
		return false
	}
	defer client.Close()
	return true
}

func TryConnectServerV2(ipPort string, password string, user string) (err error) {
	// 设置客户端请求参数
	config := &ssh.ClientConfig{
		User: user,
		// 支持公钥认证和密码验证
		Auth: []ssh.AuthMethod{
			//addIdRsaFileAuth(),
			ssh.Password(password),
		},
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 忽略主机密钥
		Timeout:         1000 * time.Millisecond,
	}

	// 作为客户端连接SSH服务器
	client, err := ssh.Dial("tcp", ipPort, config)
	if err != nil {
		var errOp *net.OpError
		if errors.As(err, &errOp) {
			//err = &NetworkError{Err: errOp}
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
	authMethod := ssh.PublicKeys(privateKey)

	return authMethod

}

// SSHScanner 扫描ssh服务器
// 192.168.*.*;
// 第一个参数: 3或者6
// 第二个参数: 范围
// Example: core.SSHScanner(3, 200, 245, "root", "123456")
func SSHScanner(prefix, start, end int, user, password string) {
	// 构建队列和启动并发
	// 完成go前需要设置done
	var wg sync.WaitGroup
	taskNum := end - start + 1
	wg.Add(taskNum)
	for i := start; i <= end; i++ {
		go func(ip int) {
			defer wg.Done()
			ipAddr := fmt.Sprintf("192.168.%v.%v:22", prefix, ip)
			ok := TryConnectServer(ipAddr, password, user)
			if ok {
				fmt.Printf("%v\n", fmt.Sprintf("192.168.%v.%v", prefix, ip))
			} else {
			}
		}(i)
	}
	wg.Wait()
}

func SSHScannerV2(prefix, start, end int, user, password string) {
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
		go func(ip int) {
			defer wg.Done()
			ipAddr := fmt.Sprintf("192.168.%v.%v:22", prefix, ip)
			err := TryConnectServerV2(ipAddr, password, user)
			if err == nil {
				okChan <- ipAddr
			} else if errors.Is(err, AuthError) {
				authChan <- ipAddr
			} else {
				networkChan <- ipAddr
			}
		}(i)
	}
	wg.Wait()
	close(doneChan)

	fmt.Println("认证失败:")
	for _, ip := range authArr {
		fmt.Println(ip)
	}
	fmt.Println()

	//fmt.Println("网络错误:")
	//for _, ip := range networkArr {
	//	fmt.Println(ip)
	//}

	fmt.Println("成功登录:")
	for _, ip := range okArr {
		fmt.Println(ip)
	}
}
