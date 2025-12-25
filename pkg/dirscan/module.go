//go:build passive

package dirscan

import "veo/pkg/utils/logger"

// ModuleStatus 模块状态
type ModuleStatus int

const (
	ModuleStatusStopped ModuleStatus = iota // 已停止
	ModuleStatusStarted                     // 已启动
	ModuleStatusError                       // 错误状态
)

// DirscanModule 目录扫描模块包装器
type DirscanModule struct {
	addon  *DirscanAddon
	status ModuleStatus
}

// NewDirscanModule 创建目录扫描模块
func NewDirscanModule(col *Collector) (*DirscanModule, error) {
	addon, err := CreateDefaultAddon()
	if err != nil {
		return nil, err
	}

	if col != nil {
		addon.SetCollector(col)
	}

	module := &DirscanModule{
		addon:  addon,
		status: ModuleStatusStopped,
	}

	return module, nil
}

// SetProxy 设置代理
func (dm *DirscanModule) SetProxy(proxyURL string) {
	if dm.addon != nil {
		dm.addon.SetProxy(proxyURL)
	}
}

// Start 启动模块
func (dm *DirscanModule) Start() error {
	if dm.status == ModuleStatusStarted {
		return nil
	}

	// 启用addon
	dm.addon.Enable()

	dm.status = ModuleStatusStarted
	return nil
}

// Stop 停止模块
func (dm *DirscanModule) Stop() error {
	if dm.status == ModuleStatusStopped {
		logger.Debug("模块已经停止")
		return nil
	}

	// 禁用addon
	dm.addon.Disable()
	dm.status = ModuleStatusStopped
	logger.Debug("模块停止成功")
	return nil
}

// GetAddon 获取addon实例
func (dm *DirscanModule) GetAddon() *DirscanAddon {
	return dm.addon
}
