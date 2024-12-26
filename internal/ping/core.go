package ping

import (
	"fmt"
	"sync"

	"github.com/duke-git/lancet/v2/formatter"
	"github.com/duke-git/lancet/v2/netutil"
	"github.com/duke-git/lancet/v2/slice"

	"github.com/Runninginsilence1/scanner/internal/ip_gen"
	"github.com/Runninginsilence1/scanner/pkg/ip_helper"
)

// 用来测试ping命令

type Result struct {
	List []string `json:"list"`
}

func Single(host string) (ok bool) {
	ok = netutil.IsPingConnected(host)
	return
}

func Parallel(prefix, start, end int, format string) {
	var wg sync.WaitGroup
	taskNum := end - start + 1
	wg.Add(taskNum)

	okList := make([]string, 0, 10)
	failList := make([]string, 0, 10)

	for i := start; i <= end; i++ {
		go func(ip int) {
			defer wg.Done()
			ipAddr := ip_gen.GetIp(prefix, ip)
			//now := time.Now()
			ok := Single(ipAddr)
			if ok {
				okList = append(okList, ipAddr)
			} else {
				failList = append(failList, ipAddr)
			}
		}(i)
	}
	wg.Wait()

	slice.SortBy(okList, func(a, b string) bool {
		i := ip_helper.GetIpLast(a)
		j := ip_helper.GetIpLast(b)
		return i < j
	})

	output(okList, format)
	return
}

func output(list []string, format string) {
	if format == "json" {
		r := new(Result)
		r.List = list
		pretty, _ := formatter.Pretty(r)
		fmt.Println(pretty)
	} else {
		if len(list) != 0 {
			fmt.Println("可用主机:")
			for _, ip := range list {
				fmt.Println(ip)
			}
		} else {
			fmt.Println("无可用主机")
		}
	}
}
