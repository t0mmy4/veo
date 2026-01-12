package fingerprint

import (
	"fmt"
	"strings"
	"time"

	"veo/pkg/utils/logger"
)

// matchRule 匹配单个规则
func (e *Engine) matchRule(rule *FingerprintRule, ctx *DSLContext) *FingerprintMatch {
	// 如果没有DSL表达式，直接返回nil
	if len(rule.DSL) == 0 {
		return nil
	}

	// 获取条件类型，默认为"or"
	condition := strings.ToLower(strings.TrimSpace(rule.Condition))
	if condition == "" {
		condition = "or"
	}

	matchedDSLs := make([]string, 0)

	// 根据条件类型执行匹配
	switch condition {
	case "and":
		// AND条件：所有DSL表达式都必须匹配
		for _, dsl := range rule.DSL {
			if e.dslParser.EvaluateDSL(dsl, ctx) {
				matchedDSLs = append(matchedDSLs, dsl)
			} else {
				// 有一个不匹配就返回nil
				return nil
			}
		}
		// 所有表达式都匹配成功
		if len(matchedDSLs) == len(rule.DSL) {
			snippet := ""
			if e.shouldCaptureSnippet(rule) {
				for _, dsl := range matchedDSLs {
					snippet = e.extractSnippetForDSL(dsl, ctx)
					if snippet != "" {
						break
					}
				}
			}
			matchedExpr := fmt.Sprintf("AND(%s)", strings.Join(matchedDSLs, " && "))
			return &FingerprintMatch{
				URL:        ctx.URL,
				RuleName:   rule.Name,
				Technology: rule.Name,
				Matcher:    matchedExpr,
				DSLMatched: matchedExpr,
				Timestamp:  time.Now(),
				Snippet:    snippet,
			}
		}
	case "or":
		fallthrough // OR和default使用相同逻辑
	default:
		if condition != "or" {
			logger.Warnf("不支持的条件类型: %s, 使用默认OR条件", condition)
		}
		// OR条件：任意一个DSL表达式匹配即可
		for _, dsl := range rule.DSL {
			if e.dslParser.EvaluateDSL(dsl, ctx) {
				snippet := ""
				if e.shouldCaptureSnippet(rule) {
					snippet = e.extractSnippetForDSL(dsl, ctx)
				}
				return &FingerprintMatch{
					URL:        ctx.URL,
					RuleName:   rule.Name,
					Technology: rule.Name,
					Matcher:    dsl,
					DSLMatched: dsl,
					Timestamp:  time.Now(),
					Snippet:    snippet,
				}
			}
		}
	}

	return nil
}

func (e *Engine) shouldCaptureSnippet(rule *FingerprintRule) bool {
	if rule == nil {
		return false
	}
	return e.config.ShowSnippet
}

func (e *Engine) extractSnippetForDSL(dsl string, ctx *DSLContext) string {
	if ctx == nil || strings.TrimSpace(dsl) == "" {
		return ""
	}
	snippet := e.dslParser.ExtractSnippet(dsl, ctx)
	return snippet
}
