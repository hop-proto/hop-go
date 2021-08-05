package channels

import (
	"io"
	"sync"
)

func (r *Reliable) MyCopy(w io.Writer, m sync.Mutex) (n int64, err error) {
	var count int64
	// c := make(chan int)
	// go func() {
	// 	cv.Wait()
	// 	c <- 1
	// }()
	for {
		m.Lock()
		b := make([]byte, 1)
		n, e := r.Read(b) //hang here?
		count += int64(n)
		if e != nil {
			m.Unlock()
			return count, e
		}
		w.Write(b)
		m.Unlock()
		//TODO(baumanl): finalize that this function closes correctly according to WriteTo interface
		// if e != nil {
		// 	return count, e
		// }
	}
}
