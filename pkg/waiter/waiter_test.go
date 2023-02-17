package waiter

import (
	"testing"

	"gotest.tools/assert"
)

type testElement struct{}

func TestEmpty(t *testing.T) {
	var q Queue[testElement]

	// Notify the zero-value of a queue.
	q.Notify()

	// Register then unregister a waiter, then notify the queue.
	cnt := 0

	zero := new(testElement)

	assert.Equal(t, 0, q.l.Len())
	e := NewFunctionEntry(zero, func(e *testElement) { cnt++ })
	q.EventRegister(e)
	assert.Equal(t, 1, q.l.Len())
	q.EventUnregister(e)
	assert.Equal(t, 0, q.l.Len())
	q.Notify()
	if cnt != 0 {
		t.Errorf("Callback was called when it shouldn't have been")
	}
}
