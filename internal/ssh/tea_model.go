package ssh

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ScanResult 表示单个扫描结果
type ScanResult struct {
	IP     string
	Status string // "ok", "auth_error", "network_error"
}

// TeaModel 是 bubbletea 的模型
type TeaModel struct {
	spinner      spinner.Model
	scanning     bool
	done         bool
	okList       []string
	authErrList  []string
	networkList  []string
	resultChan   chan ScanResult
	doneChan     chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	totalScanned int
	totalIPs     int
	showAuth     bool
	showNetwork  bool
}

// NewTeaModel 创建一个新的 TeaModel
func NewTeaModel(ctx context.Context, totalIPs int, showAuth, showNetwork bool) *TeaModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	teaCtx, cancel := context.WithCancel(ctx)

	return &TeaModel{
		spinner:     s,
		scanning:    true,
		done:        false,
		okList:      []string{},
		authErrList: []string{},
		networkList: []string{},
		resultChan:  make(chan ScanResult, 100),
		doneChan:    make(chan struct{}),
		ctx:         teaCtx,
		cancel:      cancel,
		totalIPs:    totalIPs,
		showAuth:    showAuth,
		showNetwork: showNetwork,
	}
}

// Init 初始化模型
func (m *TeaModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		waitForResult(m.resultChan),
		waitForDone(m.doneChan),
	)
}

// resultMsg 包装扫描结果
type resultMsg ScanResult

// doneMsg 表示扫描完成
type doneMsg struct{}

// waitForResult 等待扫描结果
func waitForResult(resultChan chan ScanResult) tea.Cmd {
	return func() tea.Msg {
		result, ok := <-resultChan
		if !ok {
			return nil
		}
		return resultMsg(result)
	}
}

// waitForDone 等待扫描完成
func waitForDone(doneChan chan struct{}) tea.Cmd {
	return func() tea.Msg {
		<-doneChan
		return doneMsg{}
	}
}

// Update 更新模型
func (m *TeaModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.cancel() // 取消扫描
			m.scanning = false
			m.done = true
			return m, tea.Quit
		}

	case resultMsg:
		// 收到扫描结果
		m.totalScanned++
		switch msg.Status {
		case "ok":
			m.okList = append(m.okList, msg.IP)
		case "auth_error":
			m.authErrList = append(m.authErrList, msg.IP)
		case "network_error":
			m.networkList = append(m.networkList, msg.IP)
		}
		// 继续等待下一个结果
		return m, waitForResult(m.resultChan)

	case doneMsg:
		// 扫描完成
		m.scanning = false
		m.done = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View 渲染视图
func (m *TeaModel) View() string {
	var sb strings.Builder

	if m.scanning {
		sb.WriteString(fmt.Sprintf("%s 正在扫描... (已扫描: %d/%d)\n\n",
			m.spinner.View(), m.totalScanned, m.totalIPs))
	} else {
		sb.WriteString("扫描完成!\n\n")
	}

	// 显示成功连接的 IP
	if len(m.okList) > 0 {
		successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
		sb.WriteString(successStyle.Render("✓ 成功登录:") + "\n")
		for _, ip := range m.okList {
			sb.WriteString(fmt.Sprintf("  %s\n", ip))
		}
		sb.WriteString("\n")
	}

	// 显示认证失败的 IP（如果启用）
	if m.showAuth && len(m.authErrList) > 0 {
		authStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
		sb.WriteString(authStyle.Render("⚠ 认证失败:") + "\n")
		for _, ip := range m.authErrList {
			sb.WriteString(fmt.Sprintf("  %s\n", ip))
		}
		sb.WriteString("\n")
	}

	// 显示网络错误的 IP（如果启用）
	if m.showNetwork && len(m.networkList) > 0 {
		networkStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
		sb.WriteString(networkStyle.Render("✗ 网络错误:") + "\n")
		for _, ip := range m.networkList {
			sb.WriteString(fmt.Sprintf("  %s\n", ip))
		}
		sb.WriteString("\n")
	}

	if m.scanning {
		sb.WriteString(lipgloss.NewStyle().Faint(true).Render("按 q 或 Ctrl+C 退出"))
	}

	return sb.String()
}

// GetContext 返回模型的 context
func (m *TeaModel) GetContext() context.Context {
	return m.ctx
}

// SendResult 发送扫描结果到模型
func (m *TeaModel) SendResult(result ScanResult) {
	select {
	case m.resultChan <- result:
	case <-m.ctx.Done():
	}
}

// MarkDone 标记扫描完成
func (m *TeaModel) MarkDone() {
	close(m.resultChan)
	close(m.doneChan)
}

// GetResults 获取扫描结果
func (m *TeaModel) GetResults() (okList, authErrList, networkList []string) {
	return m.okList, m.authErrList, m.networkList
}
