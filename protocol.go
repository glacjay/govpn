package main

import (
	"bytes"
	"io"
	"log"
	"net"
)

const (
	kProtoControlHardResetClientV1 = 1
	kProtoControlHardResetServerV1 = 2
	kProtoControlSoftResetV1       = 3
	kProtoControlV1                = 4
	kProtoAckV1                    = 5
	kProtoDataV1                   = 6
	kProtoControlHardResetClientV2 = 7
	kProtoControlHardResetServerV2 = 8
)

type sessionId [8]byte
type ackArray []uint32

type packet struct {
	opCode    byte
	keyId     byte
	localSid  sessionId
	acks      ackArray
	remoteSid sessionId
	id        uint32
	content   []byte
}

func decodeCommonHeader(buf []byte) *packet {
	if len(buf) < 2 {
		return nil
	}
	packet := &packet{
		opCode: buf[0] >> 3,
		keyId:  buf[0] & 0x07,
	}
	packet.content = make([]byte, len(buf)-1)
	copy(packet.content, buf[1:])
	return packet
}

func sendDataPacket(conn *net.UDPConn, packet *packet) {
	buf := &bytes.Buffer{}

	//  op code and key id
	buf.WriteByte((packet.opCode << 3) | (packet.keyId & 0x07))

	//  content
	buf.Write(packet.content)

	//  sending
	_, err := conn.Write(buf.Bytes())
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}
}

func encodeCtrlPacket(packet *packet) []byte {
	buf := &bytes.Buffer{}

	//  op code and key id
	buf.WriteByte((packet.opCode << 3) | (packet.keyId & 0x07))

	//  local session id
	buf.Write(packet.localSid[:])

	//  acks
	buf.WriteByte(byte(len(packet.acks)))
	for i := 0; i < len(packet.acks); i++ {
		bufWriteUint32(buf, packet.acks[i])
	}

	//  remote session id
	if len(packet.acks) > 0 {
		buf.Write(packet.remoteSid[:])
	}

	//  packet id
	if packet.opCode != kProtoAckV1 {
		bufWriteUint32(buf, packet.id)
	}

	//  content
	buf.Write(packet.content)

	return buf.Bytes()
}

func decodeCtrlPacket(packet *packet) *packet {
	buf := bytes.NewBuffer(packet.content)

	//  remote session id
	_, err := io.ReadFull(buf, packet.localSid[:])
	if err != nil {
		return nil
	}

	//  ack array
	code, err := buf.ReadByte()
	if err != nil {
		return nil
	}
	nAcks := int(code)
	packet.acks = make([]uint32, nAcks)
	for i := 0; i < nAcks; i++ {
		packet.acks[i], err = bufReadUint32(buf)
		if err != nil {
			return nil
		}
	}

	//  local session id
	if nAcks > 0 {
		_, err = io.ReadFull(buf, packet.remoteSid[:])
		if err != nil {
			return nil
		}
	}

	//  packet id
	if packet.opCode != kProtoAckV1 {
		packet.id, err = bufReadUint32(buf)
		if err != nil {
			return nil
		}
	}

	//  content
	packet.content = buf.Bytes()

	return packet
}
