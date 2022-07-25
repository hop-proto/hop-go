package common

import (
	"sync/atomic"
	"time"
)

type AtomicBool int32

func (b *AtomicBool) IsSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *AtomicBool) SetTrue()    { atomic.StoreInt32((*int32)(b), 1) }
func (b *AtomicBool) SetFalse()   { atomic.StoreInt32((*int32)(b), 0) }

type AtomicTimeout int64

func (t *AtomicTimeout) Set(d time.Duration) {
	atomic.StoreInt64((*int64)(t), int64(d))
}

func (t *AtomicTimeout) Get() time.Duration {
	return time.Duration(atomic.LoadInt64((*int64)(t)))
}
