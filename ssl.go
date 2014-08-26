package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
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

type reliable struct {
	conn       *net.UDPConn
	netReadCh  chan *reliablePacket
	netWriteCh chan *reliablePacket

	currentPacketId uint32
	pendingPackets  map[uint32]*reliablePacket
	acks            ackArray

	keyId           byte
	localSessionId  sessionId
	remoteSessionId sessionId
}

type client struct {
	peerAddr       string
	conn           *net.UDPConn
	reliableReadCh chan *reliablePacket

	reliable reliable
}

func newClient(peerAddr string) *client {
	c := &client{
		peerAddr:       peerAddr,
		reliableReadCh: make(chan *reliablePacket),
		reliable: reliable{
			netReadCh:      make(chan *reliablePacket),
			netWriteCh:     make(chan *reliablePacket),
			pendingPackets: make(map[uint32]*reliablePacket),
		},
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < len(c.reliable.localSessionId); i++ {
		c.reliable.localSessionId[i] = byte(r.Intn(256))
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

	c.reliable.conn = c.conn
	go c.reliable.loopReading(c.conn)
	go c.reliable.loopWriting(c.reliableReadCh)

	c.handshake()
}

func (rel *reliable) loopReading(conn *net.UDPConn) {
	for {
		var buf [2000]byte
		nr, err := conn.Read(buf[:])
		if err != nil {
			log.Fatalf("can't recv packet from peer: %v", err)
		}
		packet := parseReliablePacket(buf[:nr])
		if packet != nil {
			rel.netReadCh <- packet
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
		packet.acks[i] = binary.BigEndian.Uint32(buf[:4])
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
	packet.packetId = binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]

	//  content
	packet.content = buf

	return packet
}

func (rel *reliable) loopWriting(reliableReadCh chan<- *reliablePacket) {
	for {
		var resendTimeout <-chan time.Time
		if len(rel.pendingPackets) > 0 {
			resendTimeout = time.After(time.Second)
		}

		var ackTimeout <-chan time.Time
		if len(rel.acks) > 0 {
			ackTimeout = time.After(time.Nanosecond)
		}

		select {
		case packet := <-rel.netReadCh:
			rel.acks = append(rel.acks, packet.packetId)
			log.Printf("acks: %#v", rel.acks)
			if _, ok := rel.pendingPackets[packet.packetId]; ok {
				delete(rel.pendingPackets, packet.packetId)
			}
			reliableReadCh <- packet
		case packet := <-rel.netWriteCh:
			rel.sendReliablePacket(packet)
			rel.pendingPackets[packet.packetId] = packet
		case <-resendTimeout:
			for _, packet := range rel.pendingPackets {
				rel.sendReliablePacket(packet)
				break
			}
		case <-ackTimeout:
			rel.sendReliablePacket(&reliablePacket{opCode: kProtoAckV1})
		}
	}
}

func appendUint32(buf []byte, num uint32) []byte {
	log.Printf("endian: %v", num)
	var numBuf [4]byte
	binary.BigEndian.PutUint32(numBuf[:], num)
	return append(buf, numBuf[:]...)
}

func (rel *reliable) sendReliablePacket(packet *reliablePacket) {
	log.Printf("sendReliablePacket: %#v", packet)
	var buf []byte

	//  op code and key id
	buf = append(buf, mergeOpKey(packet.opCode, rel.keyId))

	//  local session id
	buf = append(buf, rel.localSessionId[:]...)

	ackCount := byte(len(rel.acks))
	sendedAckCount := ackCount
	if sendedAckCount > 8 {
		sendedAckCount = 8
	}

	//  acks
	buf = append(buf, ackCount)
	for i := byte(0); i < sendedAckCount; i++ {
		buf = appendUint32(buf, rel.acks[i])
	}

	//  remote session id
	if ackCount > 0 {
		buf = append(buf, rel.remoteSessionId[:]...)
	}

	//  packet id
	if packet.opCode != kProtoAckV1 {
		buf = appendUint32(buf, rel.currentPacketId)
	}

	//  content
	buf = append(buf, packet.content...)
	log.Printf("buf=%#v", buf)

	//  sending
	_, err := rel.conn.Write(buf)
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}

	rel.currentPacketId++
	rel.acks = rel.acks[sendedAckCount:]
}

func (c *client) handshake() {
	hardResetPacket := &reliablePacket{
		opCode: kProtoControlHardResetClientV2,
	}
	c.reliable.netWriteCh <- hardResetPacket

	for {
		select {
		case packet := <-c.reliableReadCh:
			log.Printf("recv packet: %#v", packet)
			if bytes.Equal(c.reliable.remoteSessionId[:], make([]byte, 8)) {
				copy(c.reliable.remoteSessionId[:], packet.localSessionId[:])
			}
		}
	}
}

func main() {
	c := newClient("127.0.0.1:1194")
	c.start()
}
