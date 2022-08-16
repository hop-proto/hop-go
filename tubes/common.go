package tubes

import (
	"errors"
	"io"
	"fmt"
)

var errRecvOutOfBounds = errors.New("received dataframe out of receive window bounds")

var errClosedWrite = fmt.Errorf("write to closed tube [%w]", io.EOF)

var errInvalidPacket = errors.New("invalid packer")

var errNoDataLength = fmt.Errorf("data length missing for frame [%w]", errInvalidPacket)

