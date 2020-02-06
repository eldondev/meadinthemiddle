package main

import (
	"crypto/tls"
  "fmt"
	"net"
)

func main() {
	ca, _ := loadCA()
	sConfig := new(tls.Config)
  p_s_config :=	 &tls.Config{
			MinVersion: tls.VersionTLS12,
			//CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		}
	*sConfig = *p_s_config
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cConfig := new(tls.Config)
		cConfig.ServerName = hello.ServerName
		return genCert(&ca,[]string{hello.ServerName})
	}
	listener, err := net.Listen("tcp","localhost:9090")
	for {
		conn, err := listener.Accept()
	if err != nil {
		fmt.Println(err)
		}
		data := make([]byte, 4096)
		tlsConn := tls.Server(conn, sConfig)
    length, err := tlsConn.Read(data)
		fmt.Println("%d read", length)
		fmt.Println(tlsConn.ConnectionState().ServerName);
		tlsConn.Close();
	}
	if err != nil {
		fmt.Println(err)
		}


}
