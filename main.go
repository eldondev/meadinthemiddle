package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
)

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
	outConn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", tlsConn.ConnectionState().ServerName), &tls.Config{KeyLogWriter:os.Stdout})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer outConn.Close()
	length, err = outConn.Write(data[:length])
	if err != nil {
		fmt.Println(err)
		return
	}
	go io.Copy(outConn, tlsConn)
	io.Copy(tlsConn, outConn)
}
