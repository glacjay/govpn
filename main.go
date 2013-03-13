package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/glacjay/govpn/tun"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	flagVirtAddr   = flag.String("virt-addr", "10.8.0.1/24", "virtual IP address of my TUN/TAP device")
	flagRemoteHost = flag.String("remote-host", "localhost", "remote peer's hostname or IP address")
	flagSecretFile = flag.String("secret-file", "", "name of file which contains static secret keys")
	flagSecretDir  = flag.Int("secret-direction", -1, "direction of static secret keys: 0 for normal, 1 for inverse, and default (unset) for bidirectional")
)

const (
	maxCipherKeyLen = 64
	maxHMacKeyLen   = 64

	staticKeyHead = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyFoot = "-----END OpenVPN Static key V1-----"
)

type key2 struct {
	count int
	keys  [2]key
	encI  int
	decI  int
}

type key struct {
	cipher [maxCipherKeyLen]byte
	hmac   [maxHMacKeyLen]byte
}

func main() {
	flag.Parse()

	var keys *key2
	if *flagSecretFile != "" {
		keys = initKeysWithSecretFile(*flagSecretFile, *flagSecretDir)
	}

	remoteAddrs, err := net.LookupIP(*flagRemoteHost)
	if err != nil || len(remoteAddrs) == 0 {
		log.Fatalf("Failed to resolve remote's hostname or address: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: remoteAddrs[0], Port: 1194})
	if err != nil {
		log.Fatalf("Failed to connect to remote's UDP port: %v", err)
	}
	defer conn.Close()

	tokens := strings.Split(*flagVirtAddr, "/")
	if len(tokens) < 2 {
		log.Fatalf("Malformed virt-addr: %s", *flagVirtAddr)
	}
	virtMaskOnes, err := strconv.ParseUint(tokens[1], 10, 8)
	if err != nil {
		log.Fatalf("Malformed virt-mask: %s", *flagVirtAddr)
	}
	virtAddr := tokens[0]
	virtMask := net.IP(net.CIDRMask(int(virtMaskOnes), 32)).String()

	tunDevice := tun.New()
	tunDevice.Open()
	tunDevice.SetupAddress(virtAddr, virtMask)
	tunDevice.Start()

	go linkToTunLoop(conn, tunDevice)
	for {
		packet := <-tunDevice.ReadCh
		_, err := conn.Write(packet)
		if err != nil {
			log.Printf("[EROR] Failed to write to UDP socket: %v", err)
			return
		}
	}
}

func linkToTunLoop(conn *net.UDPConn, tunDevice *tun.Tun) {
	defer conn.Close()
	defer tunDevice.Stop()

	var buf [4096]byte
	for {
		nread, err := conn.Read(buf[:])
		if nread > 0 {
			packet := make([]byte, nread)
			copy(packet, buf[:nread])
			tunDevice.WriteCh <- packet
		}
		if nread == 0 {
			return
		}
		if err != nil {
			log.Printf("[EROR] Failed to read from UDP socket: %v", err)
			return
		}
	}
}

func readSecretFile(filename string) []byte {
	file, err := os.Open(*flagSecretFile)
	if err != nil {
		log.Fatalf("Failed to open secret file '%s': %v", *flagSecretFile, err)
	}
	scanner := bufio.NewScanner(file)
	inData := false
	content := &bytes.Buffer{}
	lineno := 0
	for scanner.Scan() {
		lineno++
		if scanner.Text() == staticKeyHead {
			inData = true
			continue
		}
		if scanner.Text() == staticKeyFoot {
			break
		}
		if inData {
			if len(scanner.Text())%2 == 1 {
				log.Fatalf("Malformed secret file: line %d has odd characters", lineno)
			}
			for i := 0; i < len(scanner.Text())/2; i++ {
				var c byte
				_, err := fmt.Sscanf(scanner.Text()[i:i+2], "%02x", &c)
				if err != nil {
					log.Fatalf("Malformed secret file: line %d has invalid hex numbers", lineno)
				}
				content.WriteByte(c)
			}
		}
	}
	return content.Bytes()
}

func initKeysWithSecretFile(filename string, direction int) *key2 {
	content := readSecretFile(filename)
	keys := &key2{count: len(content) / (maxCipherKeyLen + maxHMacKeyLen)}
	index := 0
	for i := 0; i < keys.count; i++ {
		copy(keys.keys[i].cipher[:], content[index:index+maxCipherKeyLen])
		index += maxCipherKeyLen
		copy(keys.keys[i].hmac[:], content[index:index+maxHMacKeyLen])
		index += maxHMacKeyLen
	}
	switch direction {
	case -1:
		if keys.count < 1 {
			log.Fatal("Malformed secret file: contains less than 1 complete key for bidirection")
		}
		keys.encI = 0
		keys.decI = 0
	case 0:
		if keys.count < 2 {
			log.Fatal("Malformed secret file: contains less than 2 complete key for normal direction")
		}
		keys.encI = 0
		keys.decI = 1
	case 1:
		if keys.count < 2 {
			log.Fatal("Malformed secret file: contains less than 2 complete key for inverse direction")
		}
		keys.encI = 1
		keys.decI = 0
	default:
		log.Fatal("Invalid direction setup: %v", *flagSecretDir)
	}
	return keys
}
