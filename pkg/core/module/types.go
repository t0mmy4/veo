package module

// ModuleType 模块类型
type ModuleType string

const (
	ModuleFinger  ModuleType = "finger"  // 指纹识别模块
	ModuleDirscan ModuleType = "dirscan" // 目录扫描模块
)
