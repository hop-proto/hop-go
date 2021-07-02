package channels

import (
	"container/heap"
	"testing"

	"gotest.tools/assert"
)

func TestOrdering(t *testing.T) {
	// Some items and their priorities.
	items := map[string]int{
		"banana": 3, "apple": 2, "pear": 4,
	}

	// Create a priority queue, put the items in it, and
	// establish the priority queue (heap) invariants.
	pq := make(PriorityQueue, len(items))
	i := 0
	for value, priority := range items {
		pq[i] = &Item{
			value:    []byte(value),
			priority: uint64(priority),
			index:    i,
		}
		i++
	}
	heap.Init(&pq)

	item := &Item{
		value:    []byte("orange"),
		priority: 1,
	}
	heap.Push(&pq, item)

	item = &Item{
		value:    []byte("zebra"),
		priority: 10,
	}
	heap.Push(&pq, item)

	// Take the items out; they arrive in decreasing priority order.
	assert.Equal(t, string("orange"), string(heap.Pop(&pq).(*Item).value))
	assert.Equal(t, string("apple"), string(heap.Pop(&pq).(*Item).value))
	assert.Equal(t, string("banana"), string(heap.Pop(&pq).(*Item).value))
	assert.Equal(t, string("pear"), string(heap.Pop(&pq).(*Item).value))
	assert.Equal(t, string("zebra"), string(heap.Pop(&pq).(*Item).value))
}
