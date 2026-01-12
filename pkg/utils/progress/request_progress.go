package progress

import (
	"fmt"
	"sync/atomic"
	"time"

	"veo/pkg/utils/logger"
)

type RequestProgress struct {
	label      string
	total      int64
	completed  int64
	stopChan   chan struct{}
	doneChan   chan struct{}
	stopped    int32
	useCleaner bool
}

func NewRequestProgress(label string, total int64, useCleaner bool) *RequestProgress {
	p := &RequestProgress{
		label:      label,
		total:      total,
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
		useCleaner: useCleaner,
	}
	if useCleaner {
		logger.SetLineCleaner(p.clearLine)
	}
	p.print(0)
	go p.run()
	return p
}

func (p *RequestProgress) Increment() {
	if p == nil {
		return
	}
	completed := atomic.AddInt64(&p.completed, 1)
	p.ensureTotalAtLeast(completed)
}

func (p *RequestProgress) Stop() {
	if p == nil {
		return
	}
	if !atomic.CompareAndSwapInt32(&p.stopped, 0, 1) {
		return
	}
	close(p.stopChan)
	<-p.doneChan
	if p.useCleaner {
		logger.WithOutputLock(func() {
			p.clearLine()
		})
		logger.SetLineCleaner(nil)
	}
}

func (p *RequestProgress) run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			close(p.doneChan)
			return
		case <-ticker.C:
			p.print(atomic.LoadInt64(&p.completed))
		}
	}
}

func (p *RequestProgress) print(completed int64) {
	if p == nil {
		return
	}
	logger.WithOutputLock(func() {
		total := atomic.LoadInt64(&p.total)
		fmt.Printf("\r\033[K%s [%d/%d]", p.label, completed, total)
	})
}

func (p *RequestProgress) clearLine() {
	fmt.Print("\r\033[K")
}

func (p *RequestProgress) ensureTotalAtLeast(completed int64) {
	for {
		total := atomic.LoadInt64(&p.total)
		if completed <= total {
			return
		}
		if atomic.CompareAndSwapInt64(&p.total, total, completed) {
			return
		}
	}
}
