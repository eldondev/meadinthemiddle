// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

// This sample creates a stack with TCP and IPv4 protocols on top of a TUN
// device, and listens on a port. Data received by the server in the accepted
// connections is echoed back to the clients.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/adapters/gonet"
	"github.com/google/netstack/tcpip/link/fdbased"
	"github.com/google/netstack/tcpip/link/rawfile"
	"github.com/google/netstack/tcpip/link/tun"
	"github.com/google/netstack/tcpip/network/arp"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/network/ipv6"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/tcpip/transport/udp"
)

var stream_counter uint64

var tap = flag.Bool("tap", false, "use tap istead of tun")
var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in tap device")

func main() {
	ca, _ := loadCA()
	sConfig := new(tls.Config)
	p_s_config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	}
	*sConfig = *p_s_config
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cConfig := new(tls.Config)
		cConfig.ServerName = hello.ServerName
		return genCert(&ca, []string{hello.ServerName})
	}
	sConfig.KeyLogWriter = os.Stdout
	flag.Parse()
	if len(flag.Args()) != 3 {
		log.Fatal("Usage: ", os.Args[0], " <tun-device> <local-address> <local-port>")
	}

	tunName := flag.Arg(0)
	addrName := flag.Arg(1)

	rand.Seed(time.Now().UnixNano())

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	// Parse the IP address. Support both ipv4 and ipv6.
	parsedAddr := net.ParseIP(addrName)
	if parsedAddr == nil {
		log.Fatalf("Bad IP address: %v", addrName)
	}

	var addr tcpip.Address
	var proto tcpip.NetworkProtocolNumber
	if parsedAddr.To4() != nil {
		addr = tcpip.Address(parsedAddr.To4())
		proto = ipv4.ProtocolNumber
	} else if parsedAddr.To16() != nil {
		addr = tcpip.Address(parsedAddr.To16())
		proto = ipv6.ProtocolNumber
	} else {
		log.Fatalf("Unknown IP type: %v", addrName)
	}

	// Create the stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol(), arp.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{tcp.NewProtocol(), udp.NewProtocol()},
	})

	mtu, err := rawfile.GetMTU(tunName)
	if err != nil {
		log.Fatal(err)
	}

	var fd int
	if *tap {
		fd, err = tun.OpenTAP(tunName)
	} else {
		fd, err = tun.Open(tunName)
	}
	if err != nil {
		log.Fatal(err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		EthernetHeader: *tap,
		Address:        tcpip.LinkAddress(maddr),
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := s.CreateNIC(1, linkEP); err != nil {
		log.Fatal(err)
	}

	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		log.Fatal(err)
	}
	log.Printf("+%v", addr)

	subnet, err := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", len(addr))), tcpip.AddressMask(strings.Repeat("\x00", len(addr))))
	if err != nil {
		log.Fatal(err)
	}
	if err := s.AddAddressRange(1, proto, subnet); err != nil {
		log.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})


	listener, err := gonet.NewListener(s, tcpip.FullAddress{0, "\x0A\x00\x00\x09", 443}, ipv4.ProtocolNumber)
	udplistener, err := gonet.DialUDP(s, &tcpip.FullAddress{0, "\x08\x08\x08\x08", 53}, nil, ipv4.ProtocolNumber)
	go func() error {
		udpdata := make([]byte, 4096)

		for {
			readlen, udpaddr, udperr := udplistener.ReadFrom(udpdata)
			if udperr != nil {
				return udperr
			}
			if readlen > 0 {
				log.Printf("Packet: %+v", udpdata[:readlen])
				log.Printf("Address: %+v", udpaddr)
				serveDNS(readlen, &udpaddr, udpdata, udplistener)
			}
		}
	}()
	if err != nil {
		log.Fatal("new Listener failed: ", err)
	}
	for {
		list_conn, list_err := listener.Accept()
		if list_err != nil {
			log.Printf("%+v", err)
		} else {
			go serve(list_conn, sConfig)
		}
	}
}

func serve(conn net.Conn, sConfig *tls.Config) {
	data := make([]byte, 4096)
	log.Printf("%+v", conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalPort)
	tlsConn := tls.Server(conn, sConfig)
	defer tlsConn.Close()
	length, err := tlsConn.Read(data)
	fmt.Println("%d read", length)
	fmt.Println(tlsConn.ConnectionState().ServerName)
	outConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", tlsConn.ConnectionState().ServerName, conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalPort), &tls.Config{KeyLogWriter: os.Stdout})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer outConn.Close()
	inFile, outFile := get_record_files(tlsConn.ConnectionState().ServerName)
	defer inFile.Close()
	defer outFile.Close()
	length, err = outFile.Write(data[:length])
	if err != nil {
		log.Fatal(err)
	}
	length, err = outConn.Write(data[:length])
	if err != nil {
		log.Fatal(err)
	}
	go io.Copy(outConn, io.TeeReader(tlsConn, outFile))
	io.Copy(tlsConn, io.TeeReader(outConn, inFile))
}

func get_record_files(serverName string) (inFile, outFile *os.File) {
	var err error
	if err != nil {
		log.Fatal(err)
	}
	fileString := regexp.MustCompile("[^[:alnum:]]").ReplaceAllLiteralString(fmt.Sprintf("%s-%s-%d", serverName, time.Now().Format(time.RFC3339Nano), atomic.AddUint64(&stream_counter, 1)), "_")
	inFile, err = os.Create(fileString + "in")
	if err != nil {
		log.Fatal(err)
	}
	outFile, err = os.Create(fileString + "out")
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	return inFile, outFile
}
