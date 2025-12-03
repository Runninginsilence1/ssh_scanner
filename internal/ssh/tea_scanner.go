package ssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Runninginsilence1/scanner/internal/dumper"
	"github.com/Runninginsilence1/scanner/internal/ip_gen"
)

// ScannerWithTea 使用 bubbletea 进行扫描
func ScannerWithTea(ctx context.Context, prefix, start, end int, user, password string, opt Option, format string) {
	dumpType, err := dumper.GetType(format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	calTime := time.Now()

	// 计算总 IP 数
	totalIPs := end - start + 1

	// 创建 bubbletea 模型
	model := NewTeaModel(ctx, totalIPs, opt.ShowAuth, opt.ShowNetwork)

	// 启动 bubbletea 程序
	p := tea.NewProgram(model)

	// 在后台启动扫描
	go func() {
		runScan(model, prefix, start, end, user, password, opt)
	}()

	// 运行 bubbletea UI
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running bubbletea: %v\n", err)
		return
	}

	// 获取最终结果
	teaModel := finalModel.(*TeaModel)
	okArr, authArr, networkArr := teaModel.GetResults()

	// 排序结果
	sortByIpLast(okArr)
	sortByIpLast(authArr)
	sortByIpLast(networkArr)

	// 如果是 JSON 格式，输出 JSON
	if dumpType == dumper.JSON {
		output(okArr, authArr, networkArr, opt, dumpType)
	}

	fmt.Printf("\n扫描完成, 用时: %v ms\n", time.Since(calTime).Milliseconds())
}

// runScan 执行实际的扫描逻辑
func runScan(model *TeaModel, prefix, start, end int, user, password string, opt Option) {
	ctx := model.GetContext()

	// 设置默认并发数
	maxWorkers := opt.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = 500
	}

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

				var ipAddr string
				if opt.Port > 0 && opt.Port != 22 {
					ipAddr = ip_gen.GetSshAddrWithPort(prefix, suffix, opt.Port)
				} else {
					ipAddr = ip_gen.GetSshAddr(prefix, suffix)
				}

				// Loop 模式不适用于 bubbletea，跳过
				if opt.Loop {
					continue
				}

				err := TryConnectServerV2(ctx, ipAddr, password, user, opt.EnablePubKey)
				if err == nil {
					model.SendResult(ScanResult{IP: ipAddr, Status: "ok"})
				} else if errors.Is(err, AuthError) {
					model.SendResult(ScanResult{IP: ipAddr, Status: "auth_error"})
				} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					// context 取消，不记录错误
					return
				} else {
					model.SendResult(ScanResult{IP: ipAddr, Status: "network_error"})
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

	// 标记扫描完成
	model.MarkDone()
}
