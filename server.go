package main

import (
	"net/http"
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
)

func Serve(p *Proxy) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:9090"))
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go Handle(conn, p)
	}
}

type bufferedConn struct {
    r        *bufio.Reader
    net.Conn // So that most methods are embedded
}

func newBufferedConn(c net.Conn) bufferedConn {
    return bufferedConn{bufio.NewReader(c), c}
}

func newBufferedConnSize(c net.Conn, n int) bufferedConn {
    return bufferedConn{bufio.NewReaderSize(c, n), c}
}

func (b bufferedConn) Peek(n int) ([]byte, error) {
    return b.r.Peek(n)
}

func (b bufferedConn) Read(p []byte) (int, error) {
    return b.r.Read(p)
}

func Handle(conn net.Conn, p *Proxy) {
	data := make([]byte, 4096)

	new_conn := newBufferedConn(conn)
	data, err := new_conn.Peek(4096)
	if err != nil {
		log.Printf("Error: %s", err)
	}

	hostname, hostname_err := GetHostname(data[:])
	if hostname_err == nil {
		log.Printf("Parsed hostname: %s\n", hostname)
	}
	http.Serve(&oneShotListener{new_conn},p)
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

