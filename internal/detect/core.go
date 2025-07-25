package detect

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Runninginsilence1/scanner/internal/ip_gen"
	"github.com/imroc/req/v3"
)

func Scanner(prefix, start, end int, opt Option) {
	calTime := time.Now()
	defer func() {
		fmt.Printf("扫描完成, 用时: %v ms\n", time.Now().Sub(calTime).Milliseconds())
	}()
	var wg sync.WaitGroup
	taskNum := end - start + 1
	wg.Add(taskNum)

	var (
		doneChan = make(chan struct{})
	)

	for i := start; i <= end; i++ {
		go func(suffix int) {
			defer wg.Done()
			addr := ip_gen.GetAddr(prefix, suffix, opt.Port)

			ok := detect(addr, opt.UUIDStr, opt.EnableUUID)
			if ok {
				fmt.Println(addr)
			}
		}(i)
	}
	wg.Wait()
	close(doneChan)
}

// 超时1秒
func detect(address string, uuidStr string, enableUUID bool) bool {
	// 和 exec包的Cmd不同，http状态码不会影响到错误

	cli := req.C()
	cli.SetBaseURL("http://" + address)
	cli.SetTimeout(1 * time.Second)

	get, err := cli.R().
		SetQueryParam("page", "1").
		SetQueryParam("page_size", "10").
		Get("/")

	if err != nil {
		return false
	}

	// 如果没有特殊要求，只要路由程序有响应就返回true
	if !enableUUID {
		return true
	}
	targetUUIDStr := get.String()
	if strings.EqualFold(uuidStr, targetUUIDStr) {
		return true
	}
	return false
}
