package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"net"
	"time"
)

const (
	kReliableRecvCacheSize = 8
	kReliableSendAcksCount = 4
)

type reliableUdp struct {
	stopChan      chan struct{}
	failChan      <-chan time.Time
	doneHandshake chan struct{}

	ctrlSendChan chan *packet
	conn         *net.UDPConn
	sendingPid   uint32
	waitingAck   map[uint32]chan<- struct{}

	ctrlRecvChan  <-chan *packet
	recvedPackets [kReliableRecvCacheSize]*packet
	recvingPid    uint32
	acks          ackArray
	sslRecvChan   chan *packet
	sslRecvBuf    bytes.Buffer

	connected bool
	keyId     byte
	localSid  sessionId
	remoteSid sessionId
}

func dialReliableUdp(conn *net.UDPConn, ctrlRecvChan <-chan *packet) *reliableUdp {
	ru := &reliableUdp{
		stopChan:      make(chan struct{}),
		failChan:      time.After(time.Minute),
		doneHandshake: make(chan struct{}),
		conn:          conn,
		ctrlSendChan:  make(chan *packet),
		waitingAck:    make(map[uint32]chan<- struct{}),
		ctrlRecvChan:  ctrlRecvChan,
		sslRecvChan:   make(chan *packet),
	}
	io.ReadFull(rand.Reader, ru.localSid[:])

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
	var ackTimeout <-chan time.Time
	if len(ru.acks) > 0 {
		ackTimeout = time.After(time.Microsecond)
	}

	select {
	case <-ru.stopChan:
		return false

	case <-ru.failChan:
		log.Fatalf("can't negotiate with peer within 60 seconds")

	case <-ru.doneHandshake:
		ru.failChan = nil

	case packet := <-ru.ctrlRecvChan:
		ru.recvCtrlPacket(packet)

	case packet := <-ru.ctrlSendChan:
		packet.id = ru.sendingPid
		ru.sendingPid++
		ru.waitingAck[packet.id] = ru.sendCtrlPacket(packet)

	case <-ackTimeout:
		ru.sendCtrlPacket(&packet{opCode: kProtoAckV1})
	}

	return true
}

func (ru *reliableUdp) recvCtrlPacket(packet *packet) {
	packet = decodeCtrlPacket(packet)

	if packet.opCode != kProtoAckV1 {
		ru.acks = append(ru.acks, packet.id)
	}

	for _, ack := range packet.acks {
		if _, ok := ru.waitingAck[ack]; ok {
			ru.waitingAck[ack] <- struct{}{}
			delete(ru.waitingAck, ack)
		}
	}

	if packet.id-ru.recvingPid >= kReliableRecvCacheSize {
		return
	}
	if ru.recvedPackets[packet.id-ru.recvingPid] != nil {
		return
	}
	ru.recvedPackets[packet.id-ru.recvingPid] = packet

	switch packet.opCode {
	case kProtoControlHardResetServerV2:
		copy(ru.remoteSid[:], packet.localSid[:])
		ru.connected = true

	case kProtoControlV1:
		i := 0
		for ru.recvedPackets[i] != nil {
			ru.sslRecvChan <- ru.recvedPackets[i]
			i++
			ru.recvingPid++
		}
		copy(ru.recvedPackets[:kReliableRecvCacheSize-i], ru.recvedPackets[i:])
	}
}

func (ru *reliableUdp) sendCtrlPacket(packet *packet) chan<- struct{} {
	copy(packet.localSid[:], ru.localSid[:])
	copy(packet.remoteSid[:], ru.remoteSid[:])

	nAck := len(ru.acks)
	if nAck > kReliableSendAcksCount {
		nAck = kReliableSendAcksCount
	}
	packet.acks = make(ackArray, nAck)
	copy(packet.acks, ru.acks)

	_, err := ru.conn.Write(encodeCtrlPacket(packet))
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}

	ru.acks = ru.acks[nAck:]

	if packet.opCode != kProtoAckV1 {
		packet.acks = nil
		return startRetrySendCtrlPacket(ru.conn, packet)
	}

	return nil
}

func startRetrySendCtrlPacket(conn *net.UDPConn, packet *packet) chan<- struct{} {
	stopChan := make(chan struct{})
	buf := encodeCtrlPacket(packet)
	go func() {
		totalSeconds := 0
		for i := 1; totalSeconds < 60; i *= 2 {
			totalSeconds += i
			select {
			case <-stopChan:
				return
			case <-time.After(time.Duration(i) * time.Second):
				_, err := conn.Write(buf)
				if err != nil {
					log.Fatalf("can't send packet to peer: %v", err)
				}
			}
		}
		log.Fatalf("can't negotiate with peer within 60 seconds: %v", packet.id)
	}()
	return stopChan
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
