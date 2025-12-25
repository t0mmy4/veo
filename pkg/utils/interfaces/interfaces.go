package interfaces

import "veo/pkg/types"

// 核心业务接口定义

// URLCollectorInterface URL采集器接口
// 负责URL的收集、存储和管理
type URLCollectorInterface interface {
	// 获取收集的URL映射表
	GetURLMap() map[string]int
	// 获取收集的URL数量
	GetURLCount() int
}

// 数据结构定义

// HTTPResponse HTTP响应结构体
// 用于在各个模块之间传递HTTP响应数据
type HTTPResponse = types.HTTPResponse

// FilterResult 过滤结果结构体
// 包含过滤操作的完整结果信息
type FilterResult = types.FilterResult

// PageHash 页面哈希信息结构体
// 用于无效页面检测和统计
type PageHash = types.PageHash

// 指纹识别相关接口

// FingerprintAnalyzer 指纹分析器接口（用于跨模块调用，避免反射）
type FingerprintAnalyzer interface {
	// AnalyzeResponseWithClientSilent 分析响应包并进行指纹识别（静默版本）
	AnalyzeResponseWithClientSilent(response *HTTPResponse, httpClient interface{}) []*FingerprintMatch
}

// FingerprintMatch 指纹匹配结果
type FingerprintMatch = types.FingerprintMatch
