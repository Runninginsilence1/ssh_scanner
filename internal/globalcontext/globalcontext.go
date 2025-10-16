package globalcontext

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

var Ctx context.Context
var Cancel context.CancelFunc

func init() {
	// 创建可取消的 context
	Ctx, Cancel = context.WithCancel(context.Background())

	// 监听系统信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// 在后台 goroutine 中处理信号
	go func() {
		<-sigChan
		// 收到信号时取消全局 context
		Cancel()
	}()
}
