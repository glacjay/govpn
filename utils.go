package main

import (
	"bytes"
	"encoding/binary"
	"io"
)

type stopChan chan struct{}

func bufReadUint32(buf *bytes.Buffer) (uint32, error) {
	var numBuf [4]byte
	_, err := io.ReadFull(buf, numBuf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(numBuf[:]), nil
}

func bufWriteUint32(buf *bytes.Buffer, num uint32) {
	var numBuf [4]byte
	binary.BigEndian.PutUint32(numBuf[:], num)
	buf.Write(numBuf[:])
}
