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
	"sync/atomic"
	"time"
)

type udpReceiver struct {
	conn     *net.UDPConn
	stopFlag uint32
	ctrlChan chan<- *packet
	dataChan chan<- *packet
}

func (ur *udpReceiver) start() {
	go func() {
		for {
			if !ur.iterate() {
				break
			}
		}
	}()
}

func (ur *udpReceiver) stop() {
	atomic.StoreUint32(&ur.stopFlag, 1)
	ur.conn.Close()
}

func (ur *udpReceiver) iterate() bool {
	var buf [2048]byte
	nr, err := ur.conn.Read(buf[:])
	if err != nil {
		if stopFlag := atomic.LoadUint32(&ur.stopFlag); stopFlag == 1 {
			return false
		}
		if netErr, ok := err.(net.Error); ok {
			if netErr.Temporary() {
				log.Printf("ERROR udp recv: %v", netErr)
				return true
			} else {
				log.Fatalf("FATAL udp recv: %v", netErr)
			}
		} else {
			log.Fatalf("FATAL udp recv: %v", err)
		}
	}

	packet := decodeCommonHeader(buf[:nr])
	if packet != nil {
		if packet.opCode == kProtoDataV1 {
			ur.dataChan <- packet
		} else {
			ur.ctrlChan <- packet
		}
	}

	return true
}

type keys struct {
	encryptCipher [16]byte
	encryptDigest [20]byte
	decryptCipher [16]byte
	decryptDigest [20]byte
}

type dataTransporter struct {
	conn     *net.UDPConn
	stopChan chan struct{}

	cipherRecvChan <-chan *packet
	plainSendChan  chan<- []byte
	plainRecvChan  <-chan []byte

	keys *keys
}

func (dt *dataTransporter) start() {
	go func() {
		for {
			if !dt.iterate() {
				break
			}
		}
	}()
}

func (dt *dataTransporter) stop() {
	dt.stopChan <- struct{}{}
}

func (dt *dataTransporter) iterate() bool {
	select {
	case <-dt.stopChan:
		return false

	case packet := <-dt.cipherRecvChan:
		plain := dt.decrypt(packet.content)
		dt.plainSendChan <- plain

	case plain := <-dt.plainRecvChan:
		packet := &packet{
			opCode:  kProtoDataV1,
			content: dt.encrypt(plain),
		}
		sendDataPacket(dt.conn, packet)
	}

	return true
}

func (dt *dataTransporter) decrypt(content []byte) []byte {
	hasher := hmac.New(sha1.New, dt.keys.decryptDigest[:])
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
	blocker, _ := aes.NewCipher(dt.keys.decryptCipher[:])
	decrypter := cipher.NewCBCDecrypter(blocker, iv)
	plain := make([]byte, len(content))
	decrypter.CryptBlocks(plain, content)

	//packetId := binary.BigEndian.Uint32(plain[:4])
	//plain = plain[4:]
	paddingLen := int(plain[len(plain)-1])
	if paddingLen > len(plain) {
		log.Printf("ERROR invalid padding")
		return nil
	}
	plain = plain[:len(plain)-paddingLen]

	return plain
}

func (dt *dataTransporter) encrypt(plain []byte) []byte {
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
	blocker, _ := aes.NewCipher(dt.keys.encryptCipher[:])
	encrypter := cipher.NewCBCEncrypter(blocker, iv)
	encrypter.CryptBlocks(content[20+16:], content[20+16:])

	hasher := hmac.New(sha1.New, dt.keys.encryptDigest[:])
	hasher.Write(content[20:])
	copy(content[:20], hasher.Sum(nil))

	return content
}

type tlsTransporter struct {
	stopChan chan struct{}

	reliableUdp *reliableUdp
	conn        *tls.Conn

	keysChan chan<- *keys
	sendChan <-chan string
	recvChan chan<- string
}

func newTlsTransporter(reliableUdp *reliableUdp, keysChan chan<- *keys,
	sendChan <-chan string, recvChan chan<- string) *tlsTransporter {

	return &tlsTransporter{
		stopChan:    make(chan struct{}),
		reliableUdp: reliableUdp,
		keysChan:    keysChan,
		sendChan:    sendChan,
		recvChan:    recvChan,
	}
}

func (tt *tlsTransporter) start() {
	tt.handshake()
	go func() {
		for {
			if !tt.iterate() {
				break
			}
		}
	}()
}

func (tt *tlsTransporter) stop() {
	tt.stopChan <- struct{}{}
}

type keySource2 struct {
	preMaster [48]byte
	random1   [32]byte
	random2   [32]byte
}

func (tt *tlsTransporter) handshake() {
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
		InsecureSkipVerify: true,
	}
	tt.conn = tls.Client(tt.reliableUdp, tlsConfig)
	err = tt.conn.Handshake()
	if err != nil {
		log.Fatalf("can't handshake tls with remote: %v", err)
	}

	localKeySource := &keySource2{}
	remoteKeySource := &keySource2{}

	//  openvpn client send key
	buf := &bytes.Buffer{}
	//  uint32 0
	buf.Write([]byte{0, 0, 0, 0})
	//  key method
	buf.WriteByte(2)
	//  key material
	io.ReadFull(rand.Reader, localKeySource.preMaster[:])
	buf.Write(localKeySource.preMaster[:])
	io.ReadFull(rand.Reader, localKeySource.random1[:])
	buf.Write(localKeySource.random1[:])
	io.ReadFull(rand.Reader, localKeySource.random2[:])
	buf.Write(localKeySource.random2[:])
	//  options string
	optionsString := "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(optionsString)+1))
	buf.Write(lenBuf)
	buf.WriteString(optionsString)
	buf.WriteByte(0)
	//  username and password
	buf.Write([]byte{0, 0, 0, 0})
	_, err = tt.conn.Write(buf.Bytes())
	if err != nil {
		log.Fatalf("can't send key to remote: %v", err)
	}

	recvBuf := make([]byte, 1024)
	_, err = tt.conn.Read(recvBuf)
	if err != nil {
		log.Fatalf("can't get key from remote: %v", err)
	}
	//copy(remoteKeySource.preMaster[:], recvBuf[5:53])
	copy(remoteKeySource.random1[:], recvBuf[5:37])
	copy(remoteKeySource.random2[:], recvBuf[37:69])

	master := make([]byte, 48)
	prf(localKeySource.preMaster[:], "OpenVPN master secret",
		localKeySource.random1[:], remoteKeySource.random1[:],
		nil, nil, master)
	keyBuf := make([]byte, 256)
	prf(master, "OpenVPN key expansion",
		localKeySource.random2[:], remoteKeySource.random2[:],
		tt.reliableUdp.localSid[:], tt.reliableUdp.remoteSid[:], keyBuf)

	keys := &keys{}
	copy(keys.encryptCipher[:], keyBuf[:16])
	copy(keys.encryptDigest[:], keyBuf[64:84])
	copy(keys.decryptCipher[:], keyBuf[128:144])
	copy(keys.decryptDigest[:], keyBuf[192:212])
	tt.keysChan <- keys

	log.Printf("done negotiate initial keys")
}

func (tt *tlsTransporter) iterate() bool {
	time.Sleep(time.Second)
	return true
}

type client struct {
	peerAddr string
	conn     *net.UDPConn

	plainSendChan chan []byte
	plainRecvChan chan []byte

	udpRecv     *udpReceiver
	reliableUdp *reliableUdp
	tlsTrans    *tlsTransporter
	dataTrans   *dataTransporter
}

func newClient(peerAddr string) *client {
	c := &client{
		peerAddr:      peerAddr,
		plainSendChan: make(chan []byte),
		plainRecvChan: make(chan []byte),
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

	ciphertextRecvChan := make(chan *packet)
	ctrlRecvChan := make(chan *packet)
	c.udpRecv = &udpReceiver{
		conn:     c.conn,
		dataChan: ciphertextRecvChan,
		ctrlChan: ctrlRecvChan,
	}
	c.udpRecv.start()

	c.reliableUdp = dialReliableUdp(c.conn, ctrlRecvChan)

	keysChan := make(chan *keys, 1)
	c.tlsTrans = newTlsTransporter(c.reliableUdp, keysChan, nil, nil)
	c.tlsTrans.start()
	keys := <-keysChan

	c.dataTrans = &dataTransporter{
		conn:           c.conn,
		stopChan:       make(chan struct{}),
		cipherRecvChan: ciphertextRecvChan,
		plainSendChan:  c.plainSendChan,
		plainRecvChan:  c.plainRecvChan,
		keys:           keys,
	}
	c.dataTrans.start()

	for {
		plain := <-c.plainSendChan
		log.Printf("recv from server: %#v", plain)
		c.plainRecvChan <- plain
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
