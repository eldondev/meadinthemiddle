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

// Package arp implements the ARP network protocol. It is used to resolve
// IPv4 addresses into link-local MAC addresses, and advertises IPv4
// addresses of its stack with the local network.
//
// To use it in the networking stack, pass arp.NewProtocol() as one of the
// network protocols when calling stack.New. Then add an "arp" address to every
// NIC on the stack that should respond to ARP requests. That is:
//
//	if err := s.AddAddress(1, arp.ProtocolNumber, "arp"); err != nil {
//		// handle err
//	}
package main

import (
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/stack"
)

const (
	// ProtocolNumber is the ARP protocol number.
	ProtocolNumber = header.ARPProtocolNumber

	// ProtocolAddress is the address expected by the ARP endpoint.
	ProtocolAddress = tcpip.Address("arp")
)

// endpoint implements stack.NetworkEndpoint.
type endpoint struct {
	nicID         tcpip.NICID
	linkEP        stack.LinkEndpoint
	linkAddrCache stack.LinkAddressCache
	addr          tcpip.Address
}

// DefaultTTL is unused for ARP. It implements stack.NetworkEndpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return 0
}

func (e *endpoint) MTU() uint32 {
	lmtu := e.linkEP.MTU()
	return lmtu - uint32(e.MaxHeaderLength())
}

func (e *endpoint) NICID() tcpip.NICID {
	return e.nicID
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &stack.NetworkEndpointID{ProtocolAddress}
}

func (e *endpoint) PrefixLen() int {
	return 0
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.ARPSize
}

func (e *endpoint) Close() {}

func (e *endpoint) WritePacket(*stack.Route, *stack.GSO, stack.NetworkHeaderParams, stack.PacketLooping, tcpip.PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// WritePackets implements stack.NetworkEndpoint.WritePackets.
func (e *endpoint) WritePackets(*stack.Route, *stack.GSO, []stack.PacketDescriptor, buffer.VectorisedView, stack.NetworkHeaderParams, stack.PacketLooping) (int, *tcpip.Error) {
	return 0, tcpip.ErrNotSupported
}

func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, loop stack.PacketLooping, pkt tcpip.PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func (e *endpoint) HandlePacket(r *stack.Route, pkt tcpip.PacketBuffer) {
	v := pkt.Data.First()
	h := header.ARP(v)
	if !h.IsValid() {
		return
	}

	switch h.Op() {
	case header.ARPRequest:
		localAddr := tcpip.Address(h.ProtocolAddressTarget())
		if localAddr != e.addr {
			return
		}
		if e.linkAddrCache.CheckLocalAddress(e.nicID, header.IPv4ProtocolNumber, localAddr) == 0 {
			return // we have no useful answer, ignore the request
		}
		hdr := buffer.NewPrependable(int(e.linkEP.MaxHeaderLength()) + header.ARPSize)
		packet := header.ARP(hdr.Prepend(header.ARPSize))
		packet.SetIPv4OverEthernet()
		packet.SetOp(header.ARPReply)
		copy(packet.HardwareAddressSender(), r.LocalLinkAddress[:])
		copy(packet.ProtocolAddressSender(), h.ProtocolAddressTarget())
		copy(packet.HardwareAddressTarget(), h.HardwareAddressSender())
		copy(packet.ProtocolAddressTarget(), h.ProtocolAddressSender())
		e.linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, tcpip.PacketBuffer{
			Header: hdr,
		})
		fallthrough // also fill the cache from requests
	case header.ARPReply:
		addr := tcpip.Address(h.ProtocolAddressSender())
		linkAddr := tcpip.LinkAddress(h.HardwareAddressSender())
		e.linkAddrCache.AddLinkAddress(e.nicID, addr, linkAddr)
	}
}

// protocol implements stack.NetworkProtocol and stack.LinkAddressResolver.
type protocol struct {
	addr tcpip.Address
}

func (p *protocol) Number() tcpip.NetworkProtocolNumber { return ProtocolNumber }
func (p *protocol) MinimumPacketSize() int              { return header.ARPSize }
func (p *protocol) DefaultPrefixLen() int               { return 0 }

func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.ARP(v)
	return tcpip.Address(h.ProtocolAddressSender()), ProtocolAddress
}

func (p *protocol) NewEndpoint(nicID tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, sender stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	if addrWithPrefix.Address != ProtocolAddress {
		return nil, tcpip.ErrBadLocalAddress
	}
	return &endpoint{
		nicID:         nicID,
		linkEP:        sender,
		linkAddrCache: linkAddrCache,
		addr:          p.addr,
	}, nil
}

// LinkAddressProtocol implements stack.LinkAddressResolver.
func (*protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv4ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.
func (*protocol) LinkAddressRequest(addr, localAddr tcpip.Address, linkEP stack.LinkEndpoint) *tcpip.Error {
	r := &stack.Route{
		RemoteLinkAddress: broadcastMAC,
	}

	hdr := buffer.NewPrependable(int(linkEP.MaxHeaderLength()) + header.ARPSize)
	h := header.ARP(hdr.Prepend(header.ARPSize))
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	copy(h.HardwareAddressSender(), linkEP.LinkAddress())
	copy(h.ProtocolAddressSender(), localAddr)
	copy(h.ProtocolAddressTarget(), addr)

	return linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, tcpip.PacketBuffer{
		Header: hdr,
	})
}

// ResolveStaticAddress implements stack.LinkAddressResolver.
func (*protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == header.IPv4Broadcast {
		return broadcastMAC, true
	}
	if header.IsV4MulticastAddress(addr) {
		// RFC 1112 Host Extensions for IP Multicasting
		//
		// 6.4. Extensions to an Ethernet Local Network Module:
		//
		// An IP host group address is mapped to an Ethernet multicast
		// address by placing the low-order 23-bits of the IP address
		// into the low-order 23 bits of the Ethernet multicast address
		// 01-00-5E-00-00-00 (hex).
		return tcpip.LinkAddress([]byte{
			0x01,
			0x00,
			0x5e,
			addr[header.IPv4AddressSize-3] & 0x7f,
			addr[header.IPv4AddressSize-2],
			addr[header.IPv4AddressSize-1],
		}), true
	}
	return "", false
}

// SetOption implements NetworkProtocol.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements NetworkProtocol.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

var broadcastMAC = tcpip.LinkAddress([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

// NewProtocol returns an ARP network protocol.
func NewProtocol(addr tcpip.Address) stack.NetworkProtocol {
	return &protocol{addr: addr}
}
