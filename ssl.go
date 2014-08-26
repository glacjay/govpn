package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
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

func mergeOpKey(opcode, keyid byte) byte {
	return (opcode << 3) | keyid
}

func splitOpKey(value byte) (byte, byte) {
	return value >> 3, value & 0x07
}

type sessionId [8]byte
type ackArray []uint32

type reliablePacket struct {
	opCode          byte
	keyId           byte
	localSessionId  sessionId
	acks            ackArray
	remoteSessionId sessionId
	packetId        uint32
	content         []byte
}

type reliableReading struct {
	ch chan *reliablePacket

	acks ackArray
}

type reliableWriting struct {
	ch chan *reliablePacket

	packetId uint32
	packets  map[uint32]*reliablePacket
}

type client struct {
	mutex sync.Mutex

	peerAddr string
	conn     *net.UDPConn

	keyId           byte
	localSessionId  sessionId
	remoteSessionId sessionId

	reliableReading reliableReading
	reliableWriting reliableWriting
}

func newClient(peerAddr string) *client {
	c := &client{
		peerAddr: peerAddr,
		keyId:    0,
		reliableReading: reliableReading{
			ch: make(chan *reliablePacket),
		},
		reliableWriting: reliableWriting{
			ch:      make(chan *reliablePacket),
			packets: make(map[uint32]*reliablePacket),
		},
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < len(c.localSessionId); i++ {
		c.localSessionId[i] = byte(r.Intn(256))
	}

	return c
}

func (c *client) start() {
	addr, err := net.ResolveUDPAddr("udp", c.peerAddr)
	if err != nil {
		log.Fatalf("can't resolve peer addr '%s': %v", c.peerAddr, err)
	}
	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("can't connect to peer: %v", err)
	}

	go c.runReliableReadingLoop(c.conn)
	go c.runReliableWritingLoop()

	c.sendHardReset()
}

func (c *client) runReliableReadingLoop(conn *net.UDPConn) {
	for {
		var buf [2000]byte
		nr, err := conn.Read(buf[:])
		if err != nil {
			log.Fatalf("can't recv packet from peer: %v", err)
		}
		packet := parseReliablePacket(buf[:nr])
		if packet != nil {
			c.reliableReading.ch <- packet
			c.reliableReading.acks = append(c.reliableReading.acks, packet.packetId)
			if _, ok := c.reliableWriting.packets[packet.packetId]; ok {
				delete(c.reliableWriting.packets, packet.packetId)
			}
			if bytes.Equal(c.remoteSessionId[:], make([]byte, 8)) {
				copy(c.remoteSessionId[:], packet.localSessionId[:])
			}
		}
	}
}

func parseReliablePacket(buf []byte) *reliablePacket {
	packet := new(reliablePacket)

	//  op code and key id
	if len(buf) < 1 {
		return nil
	}
	code := buf[0]
	packet.opCode, packet.keyId = splitOpKey(code)
	buf = buf[1:]

	//  remote session id
	if len(buf) < 8 {
		return nil
	}
	copy(packet.localSessionId[:], buf[:8])
	buf = buf[8:]

	//  ack array
	if len(buf) < 1 {
		return nil
	}
	ackCount := int(buf[0])
	buf = buf[1:]
	if len(buf) < ackCount*4 {
		return nil
	}
	packet.acks = make([]uint32, ackCount)
	for i := 0; i < ackCount; i++ {
		packet.acks[i] = binary.LittleEndian.Uint32(buf[:4])
		log.Printf("endian: %v", packet.acks[i])
		buf = buf[4:]
	}

	//  local session id
	if ackCount > 0 {
		if len(buf) < 8 {
			return nil
		}
		copy(packet.remoteSessionId[:], buf[:8])
		buf = buf[8:]
	}

	//  packet id
	if len(buf) < 4 {
		return nil
	}
	packet.packetId = binary.LittleEndian.Uint32(buf[:4])
	log.Printf("endian: %v", packet.packetId)
	buf = buf[4:]

	//  content
	packet.content = buf

	return packet
}

func (c *client) runReliableWritingLoop() {
	for {
		var resendTimeout <-chan time.Time
		if len(c.reliableWriting.packets) > 0 {
			resendTimeout = time.After(time.Second)
		}

		var ackTimeout <-chan time.Time
		if len(c.reliableReading.acks) > 0 {
			ackTimeout = time.After(time.Nanosecond)
		}

		select {
		case packet := <-c.reliableWriting.ch:
			c.sendReliablePacket(packet)
			c.reliableWriting.packets[packet.packetId] = packet
		case <-resendTimeout:
			for _, packet := range c.reliableWriting.packets {
				c.sendReliablePacket(packet)
				break
			}
		case <-ackTimeout:
			c.sendReliablePacket(&reliablePacket{opCode: kProtoAckV1})
		}
	}
}

func appendUint32(buf []byte, num uint32) []byte {
	log.Printf("endian: %v", num)
	var numBuf [4]byte
	binary.LittleEndian.PutUint32(numBuf[:], num)
	return append(buf, numBuf[:]...)
}

func (c *client) sendReliablePacket(packet *reliablePacket) {
	log.Printf("sendReliablePacket: %#v", packet)
	var buf []byte

	//  op code and key id
	buf = append(buf, mergeOpKey(packet.opCode, c.keyId))

	//  local session id
	buf = append(buf, c.localSessionId[:]...)

	ackCount := byte(len(c.reliableReading.acks))
	sendedAckCount := ackCount
	if sendedAckCount > 8 {
		sendedAckCount = 8
	}

	//  acks
	buf = append(buf, ackCount)
	for i := byte(0); i < sendedAckCount; i++ {
		buf = appendUint32(buf, c.reliableReading.acks[i])
	}

	//  remote session id
	if ackCount > 0 {
		buf = append(buf, c.remoteSessionId[:]...)
	}

	//  packet id
	if packet.opCode != kProtoAckV1 {
		buf = appendUint32(buf, c.reliableWriting.packetId)
	}

	//  content
	buf = append(buf, packet.content...)
	log.Printf("buf=%#v", buf)

	//  sending
	_, err := c.conn.Write(buf)
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}

	c.reliableWriting.packetId++
	c.reliableReading.acks = c.reliableReading.acks[sendedAckCount:]
}

func (c *client) sendHardReset() {
	hardResetPacket := &reliablePacket{
		opCode: kProtoControlHardResetClientV2,
	}
	c.reliableWriting.ch <- hardResetPacket

	packet := <-c.reliableReading.ch
	log.Printf("recv packet: %#v", packet)

	time.Sleep(time.Second)
}

func main() {
	c := newClient("192.168.56.8:1194")
	c.start()
}
