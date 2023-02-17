// Package waiter implements a a wait queue, where waiters can be registered to
// be notified of events. It is loosely based on the implementation in gVisor.
package waiter

import (
	"sync"

	"hop.computer/hop/pkg/list"
)

type Queue[T any] struct {
	l list.List[Entry[T]]
	m sync.RWMutex
}

type Entry[T any] struct {
	object   *T
	listener EventListener[T]
}

type EventListener[T any] interface {
	NotifyEvent(*T)
}

func (q *Queue[T]) EventRegister(e *Entry[T]) {
	q.m.Lock()
	defer q.m.Unlock()
	q.l.PushBack(e)
}

func (q *Queue[T]) EventUnregister(e *Entry[T]) bool {
	q.m.Lock()
	defer q.m.Unlock()
	ret := q.l.Remove(e)
	return ret
}

func (q *Queue[T]) Notify() {
	q.m.RLock()
	for e := q.l.FrontIter(); e != nil; e = e.Next() {
		entry := e.Element()
		entry.listener.NotifyEvent(entry.object)
	}
	defer q.m.RUnlock()
}

type functionNotifier[T any] func(*T)

func (f functionNotifier[T]) NotifyEvent(t *T) {
	f(t)
}

func NewFunctionEntry[T any](object *T, f func(*T)) *Entry[T] {
	e := Entry[T]{
		object:   object,
		listener: functionNotifier[T](f),
	}
	return &e
}

type channelNotifier[T any] chan *T

func (c channelNotifier[T]) NotifyEvent(t *T) {
	c <- t
}

func NewChannelEntry[T any](object *T, c chan *T) *Entry[T] {
	e := Entry[T]{
		object:   object,
		listener: channelNotifier[T](c),
	}
	return &e
}
