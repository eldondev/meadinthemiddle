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
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgraph-io/badger"
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
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var stream_counter uint64

var tap = flag.Bool("tap", false, "use tap istead of tun")
var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in tap device")
var localip = flag.String("ip", "192.168.14.151", "local address to assign")
var dns = flag.String("dns", "8.8.8.8", "local address to assign")
var db *badger.DB

func init() {
	var err error
	if db, err = badger.Open(badger.DefaultOptions("meaddb")); err == nil {
		return
	} else {
		log.Fatalf("Fatal: %v", err)
	}
}

func dbUpdate(key, value []byte) {
	err := db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, value)
		err := txn.SetEntry(e)
		return err
	})
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func dbGet(key []byte) ([]byte, error) {
	var result []byte
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		result, err = item.ValueCopy(nil)
		return err
	})
	return result, err
}

func getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cConfig := new(tls.Config)
	cConfig.ServerName = hello.ServerName
	var cert tls.Certificate
	err := db.View(func(txn *badger.Txn) error {
		var certificate, key []byte
		certificate, err := dbGet([]byte(fmt.Sprintf("%s:cert", hello.ServerName)))
		if err != nil {
			return err
		}
		key, err = dbGet([]byte(fmt.Sprintf("%s:key", hello.ServerName)))
		if certificate != nil && key != nil && err == nil {
			cert, err = tls.X509KeyPair(certificate, key)
			if err != nil {
				return err
			}
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil || x509Cert.NotAfter.Before(time.Now()) {
				return fmt.Errorf("Problem loading cert, current time:%+v expire time %+v", time.Now(), x509Cert.NotAfter)
			}
		}
		return err
	})
	if err == nil {
		log.Printf("Returning cached cert for %s", hello.ServerName)
		return &cert, nil
	}

	return genCert(&ca, []string{hello.ServerName})
}

var ca tls.Certificate

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	//files, err := ioutil.ReadDir(".")
	//for _, file := range files {
	//  if strings.HasSuffic(file, "out") {
	//		req_bytes, _ := ioutil.ReadFile(file)
	//		if bytes.Split(
	//	}

	//}

	ca, _ = loadCA()
	dnsaddress := tcpip.Address(string(net.ParseIP(*dns).To4()))
	sConfig := new(tls.Config)
	p_s_config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	}
	var proto tcpip.NetworkProtocolNumber
	proto = ipv4.ProtocolNumber
	*sConfig = *p_s_config
	sConfig.GetCertificate = getCertificate
	sConfig.KeyLogWriter = KeyLogWriter{}
	flag.Parse()
	localaddress := tcpip.Address(string(net.ParseIP(*localip).To4()))
	log.Printf("Local ip is: %+v", localaddress)
	if len(flag.Args()) != 1 {
		log.Fatal("Usage: ", os.Args[0], " <tun-device> <local-address> <local-port>")
	}

	tunName := flag.Arg(0)

	rand.Seed(time.Now().UnixNano())

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	// Create the stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol(), NewProtocol(localaddress)},
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

	subnet, err := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	if err != nil {
		log.Fatal(err)
	}
	if err := s.AddAddress(1, proto, localaddress); err != nil {
		log.Fatal(err)
	}
	if err := s.AddAddress(1, proto, dnsaddress); err != nil {
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

	listener, err := gonet.NewListener(s, tcpip.FullAddress{0, "", 443}, ipv4.ProtocolNumber)
	http_listener, err := gonet.NewListener(s, tcpip.FullAddress{0, "", 80}, ipv4.ProtocolNumber)

	go serve_local(s)
	go serve_direct(http_listener)
	go serveCert()
	udplistener, err := gonet.DialUDP(s, &tcpip.FullAddress{0, dnsaddress, 53}, nil, ipv4.ProtocolNumber)
	go func() error {
		udpdata := make([]byte, 4096)

		for {
			readlen, udpaddr, udperr := udplistener.ReadFrom(udpdata)
			if udperr != nil {
				return udperr
			}
			if readlen > 0 {
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
			log.Printf("%+v", list_err)
		} else {
			go serve(list_conn, sConfig)
		}
	}
}

func serveCert() {
	log.Printf("Serving cert")
	mux := http.NewServeMux()
	mux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling cert request")
		fmt.Fprintf(w, string(certPEM))
	})

	mux.HandleFunc("/names", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling name request")
		json, err := json.Marshal(config)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		fmt.Fprintf(w, string(json))
	})

	log.Fatal(http.ListenAndServe("127.0.0.1:9090", mux))
}

func serve_direct(direct_listener *gonet.Listener) {
	for {
		direct_conn, direct_err := direct_listener.Accept()
		if direct_err != nil {
			log.Printf("%+v", direct_err)
		} else {
			go doServeDirect(direct_conn)
		}
	}
}

func doServeDirect(direct_conn net.Conn) {
	data := make([]byte, 4096)
	var err error
	var length int
	defer direct_conn.Close()
	if length, err = direct_conn.Read(data); err == nil {
		err = db.View(func(txn *badger.Txn) error {
			_, err := txn.Get(bytes.Split(data, []byte("\n"))[0])
			return err
		})
		log.Printf("Read from direct %v", length)
		log.Printf("Connecting over direct to %s", fmt.Sprintf("%s:%d", direct_conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalAddress, direct_conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalPort))
		connectAddress := direct_conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalAddress
		connectPort := direct_conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalPort
		if strings.HasPrefix(connectAddress.String(), "10.") || strings.HasPrefix(connectAddress.String(), "192.168") || regexp.MustCompile("^172[.](1[6-9]|2[0-9]|3[01])[.]").MatchString(connectAddress.String()) {
			log.Printf("Replacing %s with 127.0.0.1", connectAddress.String())
			connectAddress = tcpip.Address(net.ParseIP("127.0.0.1").To4())
			connectPort = 9090
		}
		direct_out_conn, direct_out_conn_err := net.Dial("tcp", fmt.Sprintf("%s:%d", connectAddress, connectPort))
		defer direct_out_conn.Close()
		if direct_out_conn_err != nil {
			log.Printf("%+v", direct_out_conn_err)
		} else {
			log.Printf("Connection made")
			if _, initial_write_err := direct_out_conn.Write(data[:length]); initial_write_err == nil {
				go io.Copy(direct_conn, direct_out_conn)
				io.Copy(direct_out_conn, direct_conn)
			} else {
				log.Printf("%+v", initial_write_err)
			}
		}
	}
}

func serve_local(s *stack.Stack) {
	log.Printf("serving local")
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("%s", err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("%+v", err)
		} else {
			log.Printf("Connecting inbound socket")
			internal_conn, internal_err := gonet.DialTCP(s, tcpip.FullAddress{0, "\x0A\x00\x00\x02", 8080}, ipv4.ProtocolNumber)
			if internal_err != nil {
				log.Printf("%+v", internal_err)
			} else {
				log.Printf("Inbound Connection made")
				go func() {
					defer internal_conn.Close()
					defer conn.Close()
					go io.Copy(internal_conn, conn)
					io.Copy(conn, internal_conn)
				}()
			}

		}
	}
}

type KeyLogWriter struct {
	Session []byte
}

func (k KeyLogWriter) Write(p []byte) (n int, err error) {
	key := k.Session[:]
	shasum := sha256.Sum256(p)
	key = append(key, shasum[:]...)
	dbUpdate(key, p)
	return len(p), nil
}
func getNanoSession() []byte {
	return []byte(fmt.Sprintf("%d\x00", time.Now().UnixNano()))
}

func serve(conn net.Conn, sConfig *tls.Config) {
	data := make([]byte, 4096)
	log.Printf("%+v", conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalPort)
	tlsConn := tls.Server(conn, sConfig)
	defer tlsConn.Close()
	length, err := tlsConn.Read(data)
	fmt.Println(tlsConn.ConnectionState().ServerName)
	outConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", tlsConn.ConnectionState().ServerName, conn.(*gonet.Conn).GetEndpoint().Info().(*tcp.EndpointInfo).ID.LocalPort), &tls.Config{KeyLogWriter: KeyLogWriter{Session: getNanoSession()}})
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
	copied := make(chan int64)
	go func() {
		bytes_copied, out_copy_err := io.Copy(outConn, io.TeeReader(tlsConn, outFile))
		if out_copy_err != nil {
			log.Printf("Error copying out: %s", out_copy_err)
		}
		outConn.CloseWrite()
		copied <- bytes_copied
	}()
	total_in, in_copy_err := io.Copy(tlsConn, io.TeeReader(outConn, inFile))
	if in_copy_err != nil {
		log.Printf("Error copying in: %s", in_copy_err)
	}
	total_out := (<-copied) + int64(length)
	log.Printf("total_in: %d, total_out: %d", total_in, total_out)
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
