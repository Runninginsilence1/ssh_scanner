package port

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/duke-git/lancet/v2/formatter"
	"github.com/duke-git/lancet/v2/slice"
	"github.com/spf13/cast"

	"github.com/Runninginsilence1/scanner/internal/combiner"
	"github.com/Runninginsilence1/scanner/internal/dumper"
	"github.com/Runninginsilence1/scanner/pkg/ip_helper"
)

// 功能: 端口扫描器
// ip范围复用之前的;
// 主要是端口范围的裁定, 那指定字符串格式为纯数字或者 x-y 形式的字符串;

var (
	defaultStartPort = 22
	defaultEndPort   = 65535
	defaultTimeout   = time.Second
)

var (
	startPort = defaultStartPort
	endPort   = defaultEndPort
)

type Result struct {
	Hosts []Host `json:"hosts"`
}

type Port struct {
	Value int  `json:"value"`
	Open  bool `json:"open"`
}

type Host struct {
	Value string `json:"value"`
	Ports []Port `json:"ports"`
}

func Run(prefix, startHostSuffix, endHostSuffix int, portRange string, opt Option, format string) {
	var wg sync.WaitGroup
	dumpType, err := dumper.GetType(format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	err = parseRange(portRange)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	result := Result{}
	// host + port 双重循环, 只在内部并发
	portNum := endPort - startPort + 1
	for i := startHostSuffix; i < endHostSuffix+1; i++ {
		wg.Add(portNum)
		host := combiner.CombineHost(prefix, i)
		hostField := Host{
			Value: host,
		}

		portCh := make(chan Port)
		portChClose := make(chan bool)
		go func() {
			select {
			case <-portChClose:
				close(portCh)
				return
			case portField := <-portCh:
				hostField.Ports = append(hostField.Ports, portField)
			}
		}()

		for j := startPort; j < endPort+1; j++ {
			go func() {
				defer wg.Done()
				open := detect(host, j)
				portField := Port{
					Value: j,
					Open:  open,
				}
				portCh <- portField
			}()
		}
		slice.SortBy(hostField.Ports, func(a, b Port) bool {
			return a.Value < b.Value
		})

		result.Hosts = append(result.Hosts, hostField)
		wg.Done()
	}

	slice.SortBy(result.Hosts, func(a, b Host) bool {
		last1 := ip_helper.GetIpLast(a.Value)
		last2 := ip_helper.GetIpLast(b.Value)
		return last1 < last2
	})

	switch dumpType {
	case dumper.JSON:
		pretty, _ := formatter.Pretty(result)
		fmt.Println(pretty)
	case dumper.Console:
	default:

	}

}

func detect(host string, port int) bool {
	dial, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), defaultTimeout)
	if err != nil {
		return false
	}
	defer dial.Close()
	return true
}

func parseRange(portRange string) error {
	split := strings.Split(portRange, "-")
	if len(split) == 1 {
		e, err := cast.ToIntE(split[0])
		if err != nil {
			return err
		}
		startPort = e
		endPort = 0 // 因为用的 i <= endPort 所以这里要设置为 0
	} else if len(split) == 2 {
		e, err := cast.ToIntE(split[0])
		if err != nil {
			return err
		}
		startPort = e
		e, err = cast.ToIntE(split[1])
		if err != nil {
			return err
		}
		endPort = e
	} else {
		return fmt.Errorf("invalid port range string, example: %s", "xxx or xxx-yyy")
	}
	return nil
}
