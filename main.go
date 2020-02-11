package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"sync/atomic"
	"time"
)

var stream_counter uint64

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
	listener, err := net.Listen("tcp", "localhost:9090")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
		}
		go serve(conn, sConfig)
	}
	if err != nil {
		fmt.Println(err)
	}

}

func serve(conn net.Conn, sConfig *tls.Config) {
	data := make([]byte, 4096)
	tlsConn := tls.Server(conn, sConfig)
	defer tlsConn.Close()
	length, err := tlsConn.Read(data)
	fmt.Println("%d read", length)
	fmt.Println(tlsConn.ConnectionState().ServerName)
	outConn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", tlsConn.ConnectionState().ServerName), &tls.Config{KeyLogWriter: os.Stdout})
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
