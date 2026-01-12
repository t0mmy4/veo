package cli

import (
	"context"
	"fmt"

	"veo/internal/core/config"
)

func runCheckSimilarOnlyMode(args *CLIArgs) error {
	if args == nil {
		return fmt.Errorf("参数为空")
	}

	cfg := config.GetConfig()
	controller := NewScanController(args, cfg)

	originalNetworkCheck := args.NetworkCheck
	args.NetworkCheck = true
	targets, err := controller.parseTargets(args.Targets)
	args.NetworkCheck = originalNetworkCheck
	if err != nil {
		return fmt.Errorf("Target Parse Error: %v", err)
	}

	ctx := context.Background()
	targets, report := controller.checkSimilarTargetsWithReport(ctx, targets)
	fmt.Printf("原始目标：%d，相似度过滤：%d，超时：%d，最终：%d\n", report.Stats.Total, report.Stats.Deduped, report.Stats.Timeouts, report.Stats.Kept)
	fmt.Println("相似目标：")
	if len(report.SimilarPairs) > 0 {
		for _, pair := range report.SimilarPairs {
			fmt.Printf("%s => %s\n", pair.Target, pair.SimilarTo)
		}
	} else {
		fmt.Println("无")
	}

	fmt.Println("超时目标：")
	if len(report.TimeoutTargets) > 0 {
		for _, target := range report.TimeoutTargets {
			fmt.Println(target)
		}
	} else {
		fmt.Println("无")
	}

	fmt.Println("最终目标：")
	for _, target := range targets {
		fmt.Println(target)
	}

	return nil
}
