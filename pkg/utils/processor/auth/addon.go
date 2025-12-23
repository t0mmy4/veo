//go:build passive

package auth

import (
	"veo/pkg/utils/logger"
	"veo/proxy"
)

// AuthLearningAddon 认证学习插件 - 在代理模式下自动学习传入请求中的Authorization头部
type AuthLearningAddon struct {
	proxy.BaseAddon
	detector  *AuthDetector
	isAuthSet func() bool
}

// NewAuthLearningAddon 创建认证学习插件
func NewAuthLearningAddon() *AuthLearningAddon {
	return &AuthLearningAddon{
		detector: NewAuthDetector(),
	}
}

// SetCallbacks 设置回调函数
func (ala *AuthLearningAddon) SetCallbacks(onAuthLearned func(map[string]string), isAuthSet func() bool) {
	ala.detector.SetCallbacks(onAuthLearned)
	ala.isAuthSet = isAuthSet
}

// SetEnabled 设置是否启用认证学习
func (ala *AuthLearningAddon) SetEnabled(enabled bool) {
	ala.detector.SetEnabled(enabled)
	if enabled {
		logger.Info("Authorization头部学习功能已启用")
	} else {
		logger.Info("Authorization头部学习功能已禁用")
	}
}

// IsEnabled 检查是否启用认证学习
func (ala *AuthLearningAddon) IsEnabled() bool {
	return ala.detector.IsEnabled()
}

// Requestheaders 实现proxy.Addon接口，在请求头阶段学习Authorization认证信息
func (ala *AuthLearningAddon) Requestheaders(f *proxy.Flow) {
	if !ala.IsEnabled() {
		return
	}

	// 检查是否已经设置了认证头部（通过回调）
	if ala.isAuthSet != nil && ala.isAuthSet() {
		// logger.Debug("检测到已存在认证头部，跳过认证学习") // Reduce log noise
		return
	}

	// 从请求中学习Authorization头部
	url := f.Request.URL.String()
	ala.detector.LearnFromRequest(f.Request.Raw(), url)
}

// GetLearnedAuth 获取本次会话学习到的Authorization头部
func (ala *AuthLearningAddon) GetLearnedAuth() map[string]string {
	return ala.detector.GetDetectedSchemes()
}

// ClearLearnedAuth 清空学习到的Authorization头部
func (ala *AuthLearningAddon) ClearLearnedAuth() {
	ala.detector.ClearDetectedSchemes()
}

// HasLearnedAuth 检查是否学习到了Authorization头部
func (ala *AuthLearningAddon) HasLearnedAuth() bool {
	return ala.detector.HasDetectedSchemes()
}

// GetDetector 获取认证检测器（用于测试）
func (ala *AuthLearningAddon) GetDetector() *AuthDetector {
	return ala.detector
}

// GetName 获取插件名称
func (ala *AuthLearningAddon) GetName() string {
	return "AuthLearningAddon"
}
