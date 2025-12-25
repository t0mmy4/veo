//go:build passive

package auth

import "veo/proxy"

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

// Requestheaders 实现proxy.Addon接口，在请求头阶段学习Authorization认证信息
func (ala *AuthLearningAddon) Requestheaders(f *proxy.Flow) {
	if ala.detector == nil {
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
