// Package list implements a doubly-linked list
package list

type Node[T any] struct {
	next, prev *Node[T]
	obj        *T
}

// Next returns the next item in the list, or nil if it reaches the end of the
// list.
func (n *Node[T]) Next() *Node[T] {
	return n.next
}

// Element returns a pointer to the object at this position in the list.
func (n *Node[T]) Element() *T {
	return n.obj
}

// List implements a doubly linked-list. Member comparison is implemented based
// on pointer address, not deep content equality. Head, tail, and size are
// tracked internally, so all operations are constant time unless noted
// otherwise. The list is not thread-safe.
type List[T any] struct {
	head, tail *Node[T]
	size       int
}

// Len returns the length of the list. This function is constant time.
func (l *List[T]) Len() int {
	return l.size
}

// Front returns the first item in the list. If the list is empty, it returns
// nil. This function is constant time.
func (l *List[T]) Front() *T {
	if l.head != nil {
		return l.head.obj
	}
	return nil
}

// Back returns the last item in the list. If the list is empty, it returns nil.
// This function is constant time.
func (l *List[T]) Back() *T {
	if l.tail != nil {
		return l.tail.obj
	}
	return nil
}

// PushBack appends e to the list.
func (l *List[T]) PushBack(e *T) {
	n := Node[T]{
		next: nil,
		prev: l.tail,
		obj:  e,
	}
	if l.head == nil {
		l.head = &n
	}
	if l.tail != nil {
		l.tail.next = &n
	}
	l.tail = &n
	l.size++
}

// PopBack removes the last item from the list and returns it.
func (l *List[T]) PopBack() *T {
	if l.tail == nil {
		return nil
	}
	ret := l.tail
	if l.tail.prev != nil {
		l.tail.prev.next = nil
		l.tail = l.tail.prev
	} else {
		l.tail = nil
	}
	l.size--
	return ret.obj
}

// Remove deletes the first instance of e from the list, if present. It returns
// true if an object was removed. Objects are compared based on pointer address.
// This function is O(n).
func (l *List[T]) Remove(e *T) bool {
	it := l.head
	for it != nil {
		if it.obj != e {
			it = it.next
			continue
		}
		if it.prev != nil {
			it.prev.next = it.next
		} else {
			l.head = it.next
		}
		if it.next != nil {
			it.next.prev = it.prev
		} else {
			l.tail = it.prev
		}
		it.next = nil
		it.prev = nil
		l.size--
		return true
	}
	return false
}

// FrontIter returns an iterator at the start of the list. The iterator will be
// nil when it reaches the end of a list, or if the list is empty.
func (l *List[T]) FrontIter() *Node[T] {
	return l.head
}
