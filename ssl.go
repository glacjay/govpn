package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"hash"
	"io"
	"io/ioutil"
	"log"
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

	plainSendCh chan []byte
	plainRecvCh chan []byte

	currentPacketId uint32
	pendingPackets  map[uint32]*reliablePacket
	acks            ackArray

	keyId           byte
	localSessionId  sessionId
	remoteSessionId sessionId

	localKeySource  keySource2
	remoteKeySource keySource2

	encryptCipherKey [16]byte
	encryptDigestKey [20]byte
	decryptCipherKey [16]byte
	decryptDigestKey [20]byte
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
			plainSendCh:    make(chan []byte),
			plainRecvCh:    make(chan []byte),
			netReadBuf:     &bytes.Buffer{},
			pendingPackets: make(map[uint32]*reliablePacket),
		},
	}
	c.reliable.reliableReadCh = c.reliableReadCh
	io.ReadFull(rand.Reader, c.reliable.localSessionId[:])
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
		if buf[0]>>3 == 6 {
			plain := rel.decrypt(buf[1:nr])
			rel.plainRecvCh <- plain
			continue
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
	packet.opCode = buf[0] >> 3
	packet.keyId = buf[0] & 0x07
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

func (rel *reliable) decrypt(content []byte) []byte {
	hasher := hmac.New(sha1.New, rel.decryptDigestKey[:])
	if len(content) < hasher.Size() {
		log.Printf("ERROR plain size too small")
		return nil
	}
	hasher.Write(content[hasher.Size():])
	sig := hasher.Sum(nil)
	if !bytes.Equal(sig, content[:hasher.Size()]) {
		log.Printf("ERROR invalid signature")
		return nil
	}
	content = content[hasher.Size():]

	iv := content[:16]
	content = content[16:]
	blocker, _ := aes.NewCipher(rel.decryptCipherKey[:])
	decrypter := cipher.NewCBCDecrypter(blocker, iv)
	plain := make([]byte, len(content))
	decrypter.CryptBlocks(plain, content)

	//packetId := binary.BigEndian.Uint32(plain[:4])
	//plain = plain[4:]
	paddingLen := int(plain[len(plain)-1])
	plain = plain[:len(plain)-paddingLen]

	return plain
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
		case plain := <-rel.plainSendCh:
			packet := &reliablePacket{
				opCode:  kProtoDataV1,
				content: rel.encrypt(plain),
			}
			rel.sendReliablePacket(packet)
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
	buf = append(buf, (packet.opCode<<3)|(packet.keyId&0x07))

	var sendedAckCount int

	if packet.opCode != kProtoDataV1 {
		//  local session id
		buf = append(buf, rel.localSessionId[:]...)

		ackCount := len(rel.acks)
		sendedAckCount = ackCount
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
	}

	//  content
	buf = append(buf, packet.content...)

	//  sending
	_, err := rel.conn.Write(buf)
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}

	if packet.opCode != kProtoDataV1 {
		rel.acks = rel.acks[sendedAckCount:]
	}
}

func (rel *reliable) encrypt(plain []byte) []byte {
	paddingLen := 16 - len(plain)%16
	if paddingLen == 0 {
		paddingLen = 16
	}

	content := make([]byte, 20+16+len(plain)+paddingLen)
	iv := content[20:36]
	io.ReadFull(rand.Reader, iv)
	copy(content[20+16:], plain)
	for i := 0; i < paddingLen; i++ {
		content[i+20+16+len(plain)] = byte(paddingLen)
	}
	blocker, _ := aes.NewCipher(rel.encryptCipherKey[:])
	encrypter := cipher.NewCBCEncrypter(blocker, iv)
	encrypter.CryptBlocks(content[20+16:], content[20+16:])

	hasher := hmac.New(sha1.New, rel.encryptDigestKey[:])
	hasher.Write(content[20:])
	copy(content[:20], hasher.Sum(nil))

	return content
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
	io.ReadFull(rand.Reader, c.reliable.localKeySource.preMaster[:])
	buf.Write(c.reliable.localKeySource.preMaster[:])
	io.ReadFull(rand.Reader, c.reliable.localKeySource.random1[:])
	buf.Write(c.reliable.localKeySource.random1[:])
	io.ReadFull(rand.Reader, c.reliable.localKeySource.random2[:])
	buf.Write(c.reliable.localKeySource.random2[:])
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
	_, err = tlsConn.Read(recvBuf)
	if err != nil {
		log.Fatalf("can't get key from remote: %v", err)
	}
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
	copy(c.reliable.encryptCipherKey[:], key2[:16])
	copy(c.reliable.encryptDigestKey[:], key2[64:84])
	copy(c.reliable.decryptCipherKey[:], key2[128:144])
	copy(c.reliable.decryptDigestKey[:], key2[192:212])

	for {
		plain := <-c.reliable.plainRecvCh
		log.Printf("recv from server: %#v", plain)
		c.reliable.plainSendCh <- plain
	}
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
