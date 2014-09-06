package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"net"
	"time"
)

type reliableUdp struct {
	stopChan stopChan

	ctrlSendChan    chan *packet
	conn            *net.UDPConn
	sendingPacketId uint32
	sendingPackets  map[uint32]*packet

	ctrlRecvChan  <-chan *packet
	sslRecvChan   chan *packet
	sslRecvBuf    bytes.Buffer
	receivingAcks ackArray

	connected       bool
	keyId           byte
	localSessionId  sessionId
	remoteSessionId sessionId
}

func dialReliableUdp(conn *net.UDPConn, ctrlRecvChan <-chan *packet) *reliableUdp {
	ru := &reliableUdp{
		stopChan:       make(chan struct{}),
		conn:           conn,
		ctrlSendChan:   make(chan *packet),
		sendingPackets: make(map[uint32]*packet),
		ctrlRecvChan:   ctrlRecvChan,
		sslRecvChan:    make(chan *packet),
	}
	io.ReadFull(rand.Reader, ru.localSessionId[:])

	ru.start()
	ru.ctrlSendChan <- &packet{
		opCode: kProtoControlHardResetClientV2,
	}

	return ru
}

func (ru *reliableUdp) start() {
	go func() {
		for {
			if !ru.iterate() {
				break
			}
		}
	}()
}

func (ru *reliableUdp) stop() {
	ru.stopChan <- struct{}{}
}

func (ru *reliableUdp) iterate() bool {
	var resendTimeout <-chan time.Time
	if len(ru.sendingPackets) > 0 {
		resendTimeout = time.After(time.Second)
	}

	var ackTimeout <-chan time.Time
	if len(ru.receivingAcks) > 0 {
		ackTimeout = time.After(time.Microsecond)
	}

	select {
	case packet := <-ru.ctrlRecvChan:
		packet = decodeCtrlPacket(packet)
		ru.receivingAcks = append(ru.receivingAcks, packet.packetId)
		for _, ack := range packet.acks {
			if _, ok := ru.sendingPackets[ack]; ok {
				delete(ru.sendingPackets, ack)
			}
		}
		switch packet.opCode {
		case kProtoControlHardResetServerV2:
			copy(ru.remoteSessionId[:], packet.localSessionId[:])
			ru.connected = true
		case kProtoControlV1:
			ru.sslRecvChan <- packet
		}

	case packet := <-ru.ctrlSendChan:
		packet.packetId = ru.sendingPacketId
		ru.sendingPacketId++
		ru.sendCtrlPacket(packet)
		ru.sendingPackets[packet.packetId] = packet

	case <-resendTimeout:
		for _, packet := range ru.sendingPackets {
			ru.sendCtrlPacket(packet)
		}

	case <-ackTimeout:
		ru.sendCtrlPacket(&packet{opCode: kProtoAckV1})
	}

	return true
}

func (ru *reliableUdp) sendCtrlPacket(packet *packet) {
	copy(packet.localSessionId[:], ru.localSessionId[:])
	copy(packet.remoteSessionId[:], ru.remoteSessionId[:])

	nAcks := len(ru.receivingAcks)
	if nAcks > 4 {
		nAcks = 4
	}

	_, err := ru.conn.Write(encodeCtrlPacket(packet, ru.receivingAcks[:nAcks]))
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}

	ru.receivingAcks = ru.receivingAcks[nAcks:]
}

func (ru *reliableUdp) Close() error                       { return nil }
func (ru *reliableUdp) LocalAddr() net.Addr                { return nil }
func (ru *reliableUdp) RemoteAddr() net.Addr               { return nil }
func (ru *reliableUdp) SetDeadline(t time.Time) error      { return nil }
func (ru *reliableUdp) SetReadDeadline(t time.Time) error  { return nil }
func (ru *reliableUdp) SetWriteDeadline(t time.Time) error { return nil }

func (ru *reliableUdp) Read(b []byte) (n int, err error) {
	for ru.sslRecvBuf.Len() == 0 {
		packet := <-ru.sslRecvChan
		ru.sslRecvBuf.Write(packet.content)
	}
	return ru.sslRecvBuf.Read(b)
}

func (ru *reliableUdp) Write(b []byte) (n int, err error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	packet := &packet{
		opCode:  kProtoControlV1,
		content: buf,
	}
	ru.ctrlSendChan <- packet
	return len(b), nil
}
