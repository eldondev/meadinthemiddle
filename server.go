package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

func Serve() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:9090"))
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go Handle(conn)
	}
}

func Handle(conn net.Conn) {
	data := make([]byte, 4096)
	ok_data := make([]byte, 19)

	length, err := conn.Read(data)
	if err != nil {
		log.Printf("Error: %s", err)
	}

	hostname, hostname_err := GetHostname(data[:])
	if hostname_err == nil {
		log.Printf("Parsed hostname: %s\n", hostname)
	}

	clientConn, err := net.Dial("tcp", "localhost:8080")
	clientConn.Write([]byte(fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\n\r\n", hostname)))
	ok_length, err := clientConn.Read(ok_data)
  fmt.Printf("%v %v %s", ok_length, err, string(ok_data));
	if err != nil {
		log.Printf("Error: %s", err)
		conn.Close()
		return
	}
	n, err := clientConn.Write(data[:length])
	log.Printf("Wrote %d bytes\n", n)
	if err != nil {
		log.Printf("Error: %s", err)
		conn.Close()
		clientConn.Close()
	}
	Copycat(clientConn, conn)
}

func Copycat(client, server net.Conn) {
	defer client.Close()
	defer server.Close()

	log.Printf("Entering copy routine\n")

	doCopy := func(s, c net.Conn, cancel chan<- bool) {
		io.Copy(s, c)
		cancel <- true
	}

	cancel := make(chan bool, 2)

	go doCopy(server, client, cancel)
	go doCopy(client, server, cancel)

	select {
	case <-cancel:
		log.Printf("Disconnect\n")
		return
	}

}

