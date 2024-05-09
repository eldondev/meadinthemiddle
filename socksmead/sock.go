package main

import (
	"context"
	"fmt"
	socks5 "github.com/armon/go-socks5"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type PrintingResolver struct{}

var blocklist = []*regexp.Regexp{regexp.MustCompile(".*mozilla.*"), regexp.MustCompile(".*goog.*")}

var home = net.ParseIP("127.0.0.1")

var addrlist = []*net.IPAddr{}

func (d PrintingResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	log.Printf("resolving %s:", name)
	file, err := os.ReadFile("/dev/shm/allowlist")
	if err != nil {
		return ctx, nil, err
	}
	lines := strings.Split(string(file), "\n")
	found := false
	for _, line := range lines {
		rx := regexp.MustCompile(line)
		if rx.MatchString(name) {
			found = true
		}
	}
	if !found {
		log.Printf("Blocking %s, sending %+v", name, home)
		return ctx, home, nil
	}
	for _, r := range blocklist {
		if r.MatchString(name) {
			log.Printf("Blocking %s, sending %+v", name, home)
			return ctx, home, nil
		}
	}
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	found = false
	for _, listed := range addrlist {
		if addr.String() == listed.String() {
			found = true
		}
	}
	if !found {
		addrlist = append(addrlist, addr)
	}
	return ctx, addr.IP, err
}

func dfunc(ctx context.Context, network, address string) (net.Conn, error) {
	up, down := net.Pipe()
	if strings.HasSuffix(address, ":80") {
		go serve(down, 80, address)
		return up, nil
	}
	for _, addr := range addrlist {
		if strings.Contains(address, fmt.Sprintf("%s:443", addr.String())) {
			go serve(down, 443, addr.String())
			return up, nil
		}
	}
	log.Printf("Address not resolved: %s", address)
	return nil, fmt.Errorf("Address not resolved")
}

func socksMain() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			log.Printf("Heartbeat")
		}
	}()
	// Create a SOCKS5 server
	conf := &socks5.Config{Resolver: PrintingResolver{}, Dial: dfunc}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	host := "127.0.0.1:8000"
	if os.Getenv("LISTEN_ADDRESS") != "" {
		host = os.Getenv("LISTEN_ADDRESS")
	}
	log.Printf("Listening on %+v", host)
	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", host); err != nil {

		panic(err)
	}
}
