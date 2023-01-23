package proxy

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

func TestReliableCleanClose(t *testing.T) {
	clientA, serverA := net.Pipe()
	clientB, serverB := net.Pipe()

	testString := "hello world"

	// proxy clientA <--> clientB
	wg := ReliableProxy(serverA, serverB)

	go func() {
		// clientA logic
		n, err := clientA.Write([]byte(testString))
		assert.NilError(t, err)
		logrus.Infof("client_a: Wrote %v bytes to server_a.", n)
		err = clientA.Close()
		assert.NilError(t, err)
	}()

	go func() {
		// clientB logic
		buf := make([]byte, len(testString))
		m, err := io.ReadFull(clientB, buf)
		assert.NilError(t, err)
		logrus.Infof("client_b: Read %v bytes from server_b.", m)
		err = clientB.Close()
		assert.NilError(t, err)
	}()

	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	close := func() {
		err := serverA.Close()
		assert.NilError(t, err)
		err = serverB.Close()
		assert.NilError(t, err)
	}

	select {
	case <-c:
		logrus.Info("Wait group finished normally")
		close()
	case <-time.After(time.Second * 3):
		logrus.Info("Timed out waiting for wait group")
		close()
		<-c
	}
}

func TestReliableOneClose(t *testing.T) {
	clientA, serverA := net.Pipe()
	clientB, serverB := net.Pipe()

	testString := "hello world"

	// proxy clientA <--> clientB
	wg := ReliableProxy(serverA, serverB)

	go func() {
		// clientA logic
		n, err := clientA.Write([]byte(testString))
		assert.NilError(t, err)
		logrus.Infof("client_a: Wrote %v bytes to server_a.", n)
		clientA.Close()
	}()

	go func() {
		// clientB logic (never calls close)
		buf := make([]byte, len(testString))
		m, err := io.ReadFull(clientB, buf)
		assert.NilError(t, err)
		logrus.Infof("client_b: Read %v bytes from server_b.", m)
	}()

	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	close := func() {
		err := serverA.Close()
		assert.NilError(t, err)
		err = serverB.Close()
		assert.NilError(t, err)
	}

	select {
	case <-c:
		logrus.Info("Wait group finished normally")
		close()
	case <-time.After(time.Second * 3):
		logrus.Info("Timed out waiting for wait group")
		close()
		<-c
	}
}
