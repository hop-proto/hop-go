package transport

import (
	"sync/atomic"
	"time"
)

type atomicTimeout int64

func (t *atomicTimeout) set(d time.Duration) {
	atomic.StoreInt64((*int64)(t), int64(d))
}

func (t *atomicTimeout) get() time.Duration {
	return time.Duration(atomic.LoadInt64((*int64)(t)))
}
