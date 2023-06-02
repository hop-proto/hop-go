package transport

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"testing"

	"gotest.tools/assert"

	"github.com/sirupsen/logrus"
)

// TODO(hosono) Is there an easy way to generate these on the fly?
var tlsCertificate []byte = []byte(`-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUQzUbr+IxR50qEFApzoRFpzvvXAgwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIzMDYwMjA1NTE0M1oXDTIzMDcw
MjA1NTE0M1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAyMcCVRBEZ59k0hGEQj7rKcJpGYDPCvFmAP5WKiX8MSXq
g9Z2p1PHSnZO9bYGJ00+woQBt7H36juBCw6xfuNklWaL9MfsrZ+xIGUpJjNkY8lx
vQWgr2H60mkFa1dUGmVluMIFydRM0A/7z5blCYIMSXFg3LgRzttMnpHHVwN6kEGe
6R+NknRbeqe8CFuAN6FpBz+4AAyOfdBQlH9lgg4UVEdMzlHMLFFHaDWm8DTY6Oh6
u7ISGb/AVfEOY7J0Ph4H3U3/wNm1lWw3dDf167komevlVCyiU7vIYaWJjTaB4DAc
9NN6IWjH3/bUzThAuGYW6QRLlav7HSAQAC0hCUtiTQIDAQABo1kwVzAUBgNVHREE
DTALgglsb2NhbGhvc3QwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MB0GA1UdDgQWBBQvNW8VVFZ/HPlF2hSR3EWHr7DQ0jANBgkqhkiG9w0BAQsFAAOC
AQEALaXQNYIQvJaYC1ZT8cnCwG25ThLsMphN2zN5hqdDlEtauUZPSuJuqUhSkCJz
X82sFy/ekR0O3t/+jtXVAsUIgWpMC/q7GfHgJftlc1vi5jQEutO+KHJkqqnHNpjG
nJLxUSMX4/0mgw4SrT7Qv/wo4F7VzHCIuHV+u+atIy1kvH8UwEM/i2flgXLRZ7s6
pvJlZHk4t8+CQHQPd7XTL5w/y0vEuZhtaQr0BQg6LWoMlwfEx5t+628wGcjmVOZq
vHlFJV4e2EgygKmeH2bkqQ521xyoxDoNT3rZjOODdh/DDh/jaBHSlZqUgkS7m8Mx
L5MRY/7oKszJfn4nMNQmVi0uVA==
-----END CERTIFICATE-----`)

var tlsKey []byte = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIxwJVEERnn2TS
EYRCPuspwmkZgM8K8WYA/lYqJfwxJeqD1nanU8dKdk71tgYnTT7ChAG3sffqO4EL
DrF+42SVZov0x+ytn7EgZSkmM2RjyXG9BaCvYfrSaQVrV1QaZWW4wgXJ1EzQD/vP
luUJggxJcWDcuBHO20yekcdXA3qQQZ7pH42SdFt6p7wIW4A3oWkHP7gADI590FCU
f2WCDhRUR0zOUcwsUUdoNabwNNjo6Hq7shIZv8BV8Q5jsnQ+HgfdTf/A2bWVbDd0
N/XruSiZ6+VULKJTu8hhpYmNNoHgMBz003ohaMff9tTNOEC4ZhbpBEuVq/sdIBAA
LSEJS2JNAgMBAAECggEACGUb0Zs1xQBq6oateUigtBULKHQUlCBOU83OpAIFFrf/
Y4ZQ3UO5QkGKoSb8gGGwNVloKfpgw5Q7287AOK5A2ydXxEMkwAi8kv5v10dQVATN
AuqMkrC92FToU1nqLBVfyLciH1OHZ663aHFmf7yGj36UXn46zmOogzvUsix00Dm/
IsgQI5Cbgg6o9KCUoeXwH6vsNpoDvs/aH3BDBcAhaMfGxyVAUilH8FIkOzRN6Qv1
fNuNRvn9qKB8A4wfaIMmGXzi9gnNrdUsJhTi5lljpWIjuyPvA3qhw5GJU77XD+wm
3J+cmGxXlJTuJRP4r28CXsaCslrVmVkf+0tTj3vbqQKBgQD5/CBR4rUnVb/jU9CK
Y5TT2B/v4DEpUQn0LtQSFF09pQcS4nfA8iKdpinwz+kj9+beetgXBcmSTfProsZB
Re+wWXntn6p3e7nFitw14YigZSzgecePS6brveCWcLZSzqG8G8stoQ6j4SwP8ARF
atLafwJFXxkCraQfhcDXVBb8KQKBgQDNm8Vvhhq0L+nsh9ZB8ivUlYioqYo5xe5r
+LP+k6EVAWX2njEdzZfG62ahMM4FHI2fojeNxXxAVLjCzlzY0+2LDD/WiIgLGj+D
nVsw/Q9kGKVpHZi+6cCefsr2NvJpDydmi07D8DUlJZWpI+mpwR7BxVzPUSBegWZ3
2rxdQDN5hQKBgFkT74xeRYELvEHMJv55N5o5ZD/82mfHmc1qNmVu3j7OJHQlQNj/
LziP8lf+LiyD9L+IdKHXjRlWL7nimdS+kAd+CsWS5JKJAwySS5/jiuTkyJYArwyv
v343feT9qupc+SLnoIHU5zucTDAtrcfypcn4Ah4oIehjaZ1V8v6H11zpAoGBAMeL
Sk42JGyDo89+9Z4C3i7vATZPdGslgYMgV+/WbxrnxIFYfeqiwY64n14I86laUMiA
stHQvAnjL31AsjNtWrj8JmibEQ1VaBbf/MTKlMlccgxWQQvn6JzqCShzo0f7AQ4w
XT0kPy/SDjGdPQUW/DaqyKwb3AJcK4peqzkFOe/RAoGADRKIOTDp+Kfo4giRQrJ1
f6MPRJlRASm6PkOMtj1wiTkRHmHu273meGWZ9TtET9QPG6DApefuvwLCQgLk7rvV
REEVks8E+GNtCyClf6StMyNLcqxkDGD98HM2zJ4XddTMuIIlbqC2dFIkODw0g/0l
ir0xkE4wvTLMicn1gtlSEFQ=
-----END PRIVATE KEY-----`)

func measureThroughput(b *testing.B, w net.Conn , r net.Conn) {
	var nBytes int64 = 10 << 30  // 10 GiB

	b.ResetTimer()

	// Copy from randomness into writer
	go func() {
		_, err := io.Copy(w, rand.New(rand.NewSource(0)))
		// The copy ends when w is closed, which should cause an error
		assert.Assert(b, err != nil)
	}()

	// Copy from reader to /dev/null
	defer r.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	bufNull := bufio.NewWriter(null)
	assert.NilError(b, err)
	_, err = io.CopyN(bufNull, r, nBytes)
	assert.NilError(b, err)

	// Close the writer to end copying
	err = w.Close()
	assert.NilError(b, err)

	bytesPerSecs := float64(nBytes)/float64(b.Elapsed().Seconds())
	b.ReportMetric(bytesPerSecs/(1 << 20), "MiB/secs")
}

func BenchmarkTCP(b *testing.B) {
	listener, err := net.ListenTCP("tcp", nil)
	assert.NilError(b, err)

	c1, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	assert.NilError(b, err)

	c2, err := listener.AcceptTCP()

	measureThroughput(b, c1, c2)
}

func BenchmarkTLS(b *testing.B) {
	// Create Server
	l, err := net.ListenTCP("tcp", nil)
	assert.NilError(b, err)

	cert, err := tls.LoadX509KeyPair("testdata/localhost.crt", "testdata/localhost.key")
	assert.NilError(b, err)

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	listener := tls.NewListener(l, serverConfig)
	defer listener.Close()

	// Create Client
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	var c1 *tls.Conn
	ch := make(chan struct{})
	go func() {
		addr := "localhost:" + fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		c1, err = tls.Dial("tcp", addr, clientConfig)
		assert.NilError(b, err)
		ch<-struct{}{}
	}()
	c2, err := listener.Accept()
	assert.NilError(b, err)

	// Need to write one byte. Otherwise, the server never completes the handshake
	c2.Write([]byte{0})

	// Wait for Dial to finish
	<-ch

	measureThroughput(b, c1, c2)
}

func BenchmarkUDP(b *testing.B) {
	pktListener, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(b, err)

	c1, err := net.Dial("udp", pktListener.LocalAddr().String())
	assert.NilError(b, err)

	pktListener.Close()
	c2, err := net.DialUDP("udp", pktListener.LocalAddr().(*net.UDPAddr), c1.LocalAddr().(*net.UDPAddr))
	assert.NilError(b, err)

	measureThroughput(b, c1, c2)
}

func BenchmarkHop(b *testing.B) {
	c, h, _, stop, _, err := makeConn(b)
	assert.NilError(b, err)

	// Set a high log level so we don't need to print to the console
	logrus.SetLevel(logrus.PanicLevel)

	measureThroughput(b, c, h)
	stop()
}
