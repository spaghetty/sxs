package sxs

import ( 
	"fmt"
	"log"
	"sync"
	"github.com/akrennmair/gopcap"
	"github.com/spaghetty/sip_parser"
)

var MainWait sync.WaitGroup
var Rendering sync.WaitGroup

type DMessage struct {
	*pcap.Packet //decoded
	SipMsg *sipparser.SipMsg
}

func (d *DMessage)SrcIp() string {	
	return d.IP.SrcAddr()
}

func (d *DMessage)DestIp() string {	
	return d.IP.DestAddr()
}

func (d *DMessage)SrcPort() uint16 {
	if d.TCP!=nil {
		return d.TCP.SrcPort
	} 
	if d.UDP!=nil {
		return d.UDP.SrcPort
	}
	return 0
}

func (d *DMessage)DestPort() uint16 {
	if d.TCP!=nil {
		return d.TCP.DestPort
	} 
	if d.UDP!=nil {
		return d.UDP.DestPort
	}
	return 0
}

type SxsEngine struct {
	Container map[string] chan SxsQuery//*IpEntity
	Data chan DMessage
	Signal chan SxsQuery
	//Replies chan SxsResult
}


func NewEngine(tmp Interface) *SxsEngine {
	Output = make(chan SxsQuery)
	NewContext := &SxsEngine{Container: make(map[string] chan SxsQuery),
		Data: make(chan DMessage),
		Signal: make(chan SxsQuery),
	}
	oh := NewOutputHandler()
	go oh.Run()
	return NewContext
}

func (s *SxsEngine)Run() {
	MainWait.Add(1)
	exit := false
	for !exit {
		select {
		case msg := <- s.Data:
			if len(msg.Payload)<20 {
				continue
			}
			msg.SipMsg = sipparser.ParseMsg(string(msg.Payload))
			if _,ok := s.Container[msg.SrcIp()]; !ok {
				s.Container[msg.SrcIp()] = NewSipEntity(msg.SrcIp(), msg)
			}
			s.Container[msg.SrcIp()]<-SxsQuery{Cmd:commands["outgoing"],Udata:msg}
			if _,ok := s.Container[msg.DestIp()]; !ok {
				s.Container[msg.DestIp()] = NewSipEntity(msg.DestIp(), msg)
			}
			s.Container[msg.DestIp()]<-SxsQuery{Cmd:commands["incoming"],Udata:msg}
		case qcode := <- s.Signal:
			if(qcode.Cmd==0) {
				log.Println("exit")
				exit = true
				s.SendCommand(qcode)
				break
			}
			if(qcode.Cmd==commands["list"]) {
				Output <- qcode
				s.SendCommand(qcode)
				continue
			}
		}
	}
	MainWait.Done()
	fmt.Println("Done")
}

func (s *SxsEngine)SendMessage(msg *DMessage) {
	s.Data <- *msg
}

func (s *SxsEngine)SendCommand(q SxsQuery) {
	if q.Target=="*" { // do broadcasting
		q.Expected=len(s.Container)
		for _,e := range s.Container {
			e <- q
		}
	} else { // specific event
		q.Expected=1
	}
}

func (s *SxsEngine)SendQuery(q string) bool{
	query,ok:=NewSxsQuery(q)
	s.Signal<-query
	return ok
}

func (s *SxsEngine)SendTerm() {
	s.Signal <- SxsQuery{Target:"*",Cmd:0}
	MainWait.Wait()
	Output <- SxsQuery{Target:"*",Cmd:0}
	Rendering.Wait()
}
