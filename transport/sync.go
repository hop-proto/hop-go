package transport

import (
	"sync/atomic"
	"time"
)

type atomicBool int32

func (b *atomicBool) isSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *atomicBool) setTrue()    { atomic.StoreInt32((*int32)(b), 1) }
func (b *atomicBool) setFalse()   { atomic.StoreInt32((*int32)(b), 0) }

type atomicTimeout int64

func (t *atomicTimeout) set(d time.Duration) {
	atomic.StoreInt64((*int64)(t), int64(d))
}

func (t *atomicTimeout) get() time.Duration {
	return time.Duration(atomic.LoadInt64((*int64)(t)))
}
