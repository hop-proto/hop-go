package list

import (
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

type element struct{}

func TestPush(t *testing.T) {
	// Zero
	l := List[element]{}
	assert.Check(t, is.Nil(l.Front()))
	assert.Check(t, is.Nil(l.Back()))

	// One
	one := new(element)
	l.PushBack(one)
	assert.Equal(t, one, l.Front())
	assert.Equal(t, one, l.Back())

	// Two
	two := new(element)
	l.PushBack(two)
	assert.Equal(t, one, l.Front())
	assert.Equal(t, two, l.Back())

	// Three
	three := new(element)
	l.PushBack(three)
	assert.Equal(t, one, l.Front())
	assert.Equal(t, three, l.Back())

	// Pop them all off
	back := l.PopBack()
	assert.Equal(t, back, three)
	back = l.PopBack()
	assert.Equal(t, back, two)
	back = l.PopBack()
	assert.Equal(t, back, one)
	assert.Check(t, is.Nil(l.PopBack()))
}

func TestPop(t *testing.T) {
	l := List[element]{}
	assert.Check(t, is.Nil(l.PopBack()))
}

type intElement struct {
	n int
}

func TestRemove(t *testing.T) {
	l := List[intElement]{}
	elts := make([]*intElement, 10)
	for i := 0; i < 10; i++ {
		elts[i] = &intElement{n: i}
		l.PushBack(elts[i])
	}
	assert.Equal(t, 10, l.Len())
	{
		it := l.FrontIter()
		for i := 0; i < 10; i++ {
			assert.Check(t, is.Equal(it.Element().n, i))
			it = it.Next()
		}
		assert.Check(t, is.Nil(it))
	}

	didRemove := l.Remove(elts[7])
	assert.Equal(t, true, didRemove)
	assert.Equal(t, 9, l.Len())

	{
		it := l.FrontIter()
		assert.Assert(t, it != nil)
		for i := 0; i < 10; i++ {
			if i == 7 {
				continue
			}
			assert.Check(t, is.Equal(it.Element().n, i))
			it = it.Next()
		}
		assert.Check(t, is.Nil(it))
	}

}
