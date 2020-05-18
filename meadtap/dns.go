package main

import "strings"
import "net"
import "io"
import "log"
import "bufio"
import "bytes"
import "encoding/binary"
import "github.com/google/netstack/tcpip/adapters/gonet"

type RRecord struct {
	RecordBuffer []byte
	RRecordFooter
	Name []string
}

type RRecordFooter struct {
	Type  uint16
	Class uint16
}

type AnswerRecord struct {
	TTL     uint32
	Length  uint16
	Address [4]byte
}

type DNSPacketHeader struct {
	Id          uint16
	Flags       [2]uint8
	Questions   uint16
	Answers     uint16
	Authorities uint16
	Additionals uint16
}

type Request struct {
	DNSPacketHeader
	Records []RRecord
}

type Response struct {
	Request
	AnswerRecords []AnswerRecord
}

type Config struct {
	Hosts map[string][]net.IP
}

var config = Config{Hosts: make(map[string][]net.IP)}

func init() {
	//var err error
	//var file *os.File
	//var config_json []byte
	//if file, err = os.Open("config.json"); err == nil {
	//	if config_json, err = ioutil.ReadAll(file); err == nil {
	//		if err = json.Unmarshal(config_json, &config); err == nil {
	//			return
	//		}
	//	}
	//}
	//log.Fatalf("Fatal: %v", err)
}

func (d *DNSPacketHeader) total_records() int {
	return int(d.Questions + d.Answers + d.Authorities + d.Additionals)
}

func (record *RRecord) read_record_names(name_reader *bufio.Reader) (err error) {
	var name []byte
	for {
		var name_length byte
		if name_length, err = name_reader.ReadByte(); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if name, err = name_reader.Peek(int(name_length)); err != nil {
			return err
		}
		name_reader.Discard(int(name_length))
		record.Name = append(record.Name, string(name))
	}
	return
}

func (request *Request) read_record(packet_reader *bufio.Reader) (err error) {
	record := RRecord{}
	if record.RecordBuffer, err = packet_reader.ReadBytes('\x00'); err != nil {
		return err
	}
	name_reader := bufio.NewReader(bytes.NewReader(record.RecordBuffer))
	record.read_record_names(name_reader)
	err = binary.Read(packet_reader, binary.BigEndian, &record.RRecordFooter)
	request.Records = append(request.Records, record)
	return
}

func (response *Response) valid() bool {
	return response.Flags[0] == 1 && (response.Flags[1]|0x20 == 0x20) && response.total_records() >= 1 && response.Records[0].Type == 1 && response.Records[0].Class == 1
}

func (response *Response) populate() {
	answers, ok := config.Hosts[response.Records[0].Name[0]]
	if !ok {
		answers = make([]net.IP, 0)
		var lookups []string
		full_hostname := strings.Join(response.Records[0].Name,".")
		log.Printf("Resolving %+s", full_hostname)
		lookups, _ = net.LookupHost(full_hostname)
		for _, addr := range lookups {
			if strings.Contains(addr, ":") {
				continue
			}
		  log.Printf("Resolved %+s to %+v", response.Records[0].Name[0], addr)
			answers = append(answers, net.ParseIP(addr)) // Look up our name
			config.Hosts[full_hostname] = answers
		}
	}
	if response.valid() { // A standard query for which we have answers
		response.Flags[0], response.Flags[1] = 129, 128 // Set "we have answers" flags
		response.Answers = uint16(len(answers))
		for _, address := range answers {
			address_bytes := []byte(address.To4())
			response.AnswerRecords = append(response.AnswerRecords, AnswerRecord{TTL: 300, Length: 4, Address: [4]byte{address_bytes[0], address_bytes[1], address_bytes[2], address_bytes[3]}})
		}
	} else {
		response.Flags[0], response.Flags[1] = 129, 131 // Set "We do not have any record of that name" flags
		response.Authorities = 0
		response.Additionals = 0
	}
	response.Authorities = 0
	response.Additionals = 0
}

func (response Response) format(request Request) (packet []byte) {
	var response_packet bytes.Buffer
	response.Request = request // Copy fields to start
	response.populate()
	binary.Write(&response_packet, binary.BigEndian, response.DNSPacketHeader)
	for _, record := range response.Records {
		if record.Class != 1 {
			continue
		}
		response_packet.Write(record.RecordBuffer)
		binary.Write(&response_packet, binary.BigEndian, record.RRecordFooter)
	}
	for _, answer := range response.AnswerRecords {
		response_packet.Write([]byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}) // A reference to the offset and type of the name we are responding to because our requests are very specific
		binary.Write(&response_packet, binary.BigEndian, answer)
	}
	return response_packet.Bytes()
}

func respond(request Request, requester *net.Addr, conn *gonet.PacketConn) (err error) {
	_, err = conn.WriteTo(Response{}.format(request), *requester)
	return
}

func serveDNS(byte_count int, requester *net.Addr, packet []byte, conn *gonet.PacketConn) {
	var err error
	request := Request{}
	packet_reader := bufio.NewReader(bytes.NewReader(packet))
	if err = binary.Read(packet_reader, binary.BigEndian, &request.DNSPacketHeader); err == nil {
		request.read_record(packet_reader)
		err = respond(request, requester, conn)
	}
	if err != nil {
		log.Println("binary.Read failed:", err)
	}
}
