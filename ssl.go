package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"hash"
	"io/ioutil"
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

type keySource2 struct {
	preMaster [48]byte
	random1   [32]byte
	random2   [32]byte
}

type reliable struct {
	conn       *net.UDPConn
	netReadCh  chan *reliablePacket
	netWriteCh chan *reliablePacket
	netReadBuf *bytes.Buffer

	reliableReadCh chan *reliablePacket

	currentPacketId uint32
	pendingPackets  map[uint32]*reliablePacket
	acks            ackArray

	keyId           byte
	localSessionId  sessionId
	remoteSessionId sessionId

	localKeySource  keySource2
	remoteKeySource keySource2
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
			netReadBuf:     &bytes.Buffer{},
			pendingPackets: make(map[uint32]*reliablePacket),
		},
	}
	c.reliable.reliableReadCh = c.reliableReadCh

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
	if packet.opCode != kProtoAckV1 {
		if len(buf) < 4 {
			return nil
		}
		packet.packetId = binary.BigEndian.Uint32(buf[:4])
		buf = buf[4:]
	}

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
			for _, ack := range packet.acks {
				if _, ok := rel.pendingPackets[ack]; ok {
					delete(rel.pendingPackets, ack)
				}
			}
			switch packet.opCode {
			case kProtoControlHardResetServerV2:
				reliableReadCh <- packet
			case kProtoControlV1:
				reliableReadCh <- packet
			}
		case packet := <-rel.netWriteCh:
			if packet.opCode != kProtoAckV1 {
				packet.packetId = rel.currentPacketId
				rel.currentPacketId++
			}
			rel.sendReliablePacket(packet)
			rel.pendingPackets[packet.packetId] = packet
		case <-resendTimeout:
			for _, packet := range rel.pendingPackets {
				rel.sendReliablePacket(packet)
			}
		case <-ackTimeout:
			rel.sendReliablePacket(&reliablePacket{opCode: kProtoAckV1})
		}
	}
}

func appendUint32(buf []byte, num uint32) []byte {
	var numBuf [4]byte
	binary.BigEndian.PutUint32(numBuf[:], num)
	return append(buf, numBuf[:]...)
}

func (rel *reliable) sendReliablePacket(packet *reliablePacket) {
	var buf []byte

	//  op code and key id
	buf = append(buf, mergeOpKey(packet.opCode, rel.keyId))

	//  local session id
	buf = append(buf, rel.localSessionId[:]...)

	ackCount := len(rel.acks)
	sendedAckCount := ackCount
	if sendedAckCount > 8 {
		sendedAckCount = 8
	}

	//  acks
	buf = append(buf, byte(ackCount))
	for i := 0; i < sendedAckCount; i++ {
		buf = appendUint32(buf, rel.acks[i])
	}

	//  remote session id
	if ackCount > 0 {
		buf = append(buf, rel.remoteSessionId[:]...)
	}

	//  packet id
	if packet.opCode != kProtoAckV1 {
		buf = appendUint32(buf, packet.packetId)
	}

	//  content
	buf = append(buf, packet.content...)

	//  sending
	_, err := rel.conn.Write(buf)
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}

	rel.acks = rel.acks[sendedAckCount:]
}

func (rel *reliable) Close() error                       { return nil }
func (rel *reliable) LocalAddr() net.Addr                { return nil }
func (rel *reliable) RemoteAddr() net.Addr               { return nil }
func (rel *reliable) SetDeadline(t time.Time) error      { return nil }
func (rel *reliable) SetReadDeadline(t time.Time) error  { return nil }
func (rel *reliable) SetWriteDeadline(t time.Time) error { return nil }

func (rel *reliable) Read(b []byte) (n int, err error) {
	for rel.netReadBuf.Len() == 0 {
		packet := <-rel.reliableReadCh
		if packet.opCode == kProtoControlV1 {
			rel.netReadBuf.Write(packet.content)
		}
	}
	return rel.netReadBuf.Read(b)
}

func (rel *reliable) Write(b []byte) (n int, err error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	packet := &reliablePacket{
		opCode:  kProtoControlV1,
		content: buf,
	}
	rel.netWriteCh <- packet
	return len(b), nil
}

func (c *client) handshake() {
	hardResetPacket := &reliablePacket{
		opCode: kProtoControlHardResetClientV2,
	}
	c.reliable.netWriteCh <- hardResetPacket

	packet := <-c.reliableReadCh
	if bytes.Equal(c.reliable.remoteSessionId[:], make([]byte, 8)) {
		copy(c.reliable.remoteSessionId[:], packet.localSessionId[:])
	} else {
		log.Fatalf("this ack is not for me")
	}

	caCertFileContent, err := ioutil.ReadFile("test/ca.cer")
	if err != nil {
		log.Fatalf("can't read ca cert file: %v", err)
	}
	caCerts := x509.NewCertPool()
	ok := caCerts.AppendCertsFromPEM(caCertFileContent)
	if !ok {
		log.Fatalf("can't parse ca cert file")
	}

	clientCert, err := tls.LoadX509KeyPair("test/client.pem", "test/client.pem")
	if err != nil {
		log.Fatalf("can't load client cert and key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCerts,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(&c.reliable, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		log.Fatalf("can't handshake tls with remote: %v", err)
	}

	//  openvpn client send key
	buf := &bytes.Buffer{}
	//  uint32 0
	buf.Write([]byte{0, 0, 0, 0})
	//  key method
	buf.WriteByte(2)
	//  key material
	for i := 0; i < 48; i++ {
		b := byte(rand.Int())
		c.reliable.localKeySource.preMaster[i] = b
		buf.WriteByte(b)
	}
	for i := 0; i < 32; i++ {
		b := byte(rand.Int())
		c.reliable.localKeySource.random1[i] = b
		buf.WriteByte(b)
	}
	for i := 0; i < 32; i++ {
		b := byte(rand.Int())
		c.reliable.localKeySource.random2[i] = b
		buf.WriteByte(b)
	}
	//  options string
	optionsString := "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher BF-CBC,auth SHA1,keysize 128,key-method 2,tls-client"
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(optionsString)+1))
	buf.Write(lenBuf)
	buf.WriteString(optionsString)
	buf.WriteByte(0)
	//  username and password
	buf.Write([]byte{0, 0, 0, 0})
	_, err = tlsConn.Write(buf.Bytes())
	if err != nil {
		log.Fatalf("can't send key to remote: %v", err)
	}

	recvBuf := make([]byte, 1024)
	nr, err := tlsConn.Read(recvBuf)
	if err != nil {
		log.Fatalf("can't get key from remote: %v", err)
	}
	log.Printf("got key buf: %#v", recvBuf[:nr])
	//copy(c.reliable.remoteKeySource.preMaster[:], recvBuf[5:53])
	copy(c.reliable.remoteKeySource.random1[:], recvBuf[5:37])
	copy(c.reliable.remoteKeySource.random2[:], recvBuf[37:69])

	master := make([]byte, 48)
	prf(c.reliable.localKeySource.preMaster[:], "OpenVPN master secret",
		c.reliable.localKeySource.random1[:], c.reliable.remoteKeySource.random1[:],
		nil, nil, master)
	key2 := make([]byte, 256)
	prf(master, "OpenVPN key expansion",
		c.reliable.localKeySource.random2[:], c.reliable.remoteKeySource.random2[:],
		c.reliable.localSessionId[:], c.reliable.remoteSessionId[:], key2)
	log.Printf("encrypt cipher: %#v", key2[:16])
	log.Printf("encrypt digest: %#v", key2[64:84])
	log.Printf("decrypt cipher: %#v", key2[128:144])
	log.Printf("decrypt digest: %#v", key2[192:212])

	time.Sleep(time.Second)
}

func prf(secret []byte, label string, clientSeed, serverSeed []byte, clientSid, serverSid []byte, result []byte) {
	seed := &bytes.Buffer{}
	seed.WriteString(label)
	seed.Write(clientSeed)
	seed.Write(serverSeed)
	if clientSid != nil {
		seed.Write(clientSid)
	}
	if serverSid != nil {
		seed.Write(serverSid)
	}
	tls1Prf(seed.Bytes(), secret, result)
}

func tls1Prf(label, secret []byte, result []byte) {
	out2 := make([]byte, len(result))

	length := len(secret) / 2
	s1 := secret[:length]
	s2 := secret[length:]
	tls1Phash(md5.New, s1, label, result)
	tls1Phash(sha1.New, s2, label, out2)
	for i := 0; i < len(result); i++ {
		result[i] ^= out2[i]
	}
}

func tls1Phash(hasher func() hash.Hash, secret, seed []byte, result []byte) {
	hasher1 := hmac.New(hasher, secret)
	hasher1.Write(seed)
	a1 := hasher1.Sum(nil)

	for {
		hasher1 := hmac.New(hasher, secret)
		hasher2 := hmac.New(hasher, secret)
		hasher1.Write(a1)
		hasher2.Write(a1)
		hasher1.Write(seed)
		if len(result) > hasher1.Size() {
			out := hasher1.Sum(nil)
			copy(result, out)
			result = result[len(out):]
			a1 = hasher2.Sum(nil)
		} else {
			a1 = hasher1.Sum(nil)
			copy(result, a1)
			break
		}
	}
}

func main() {
	remoteEndpoint := flag.String("remote", "127.0.0.1:1194", "remote server address and port")
	flag.Parse()
	c := newClient(*remoteEndpoint)
	c.start()
}
