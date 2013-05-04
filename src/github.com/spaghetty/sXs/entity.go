package sxs

import (
	//"log"
	//"github.com/spaghetty/sip_parser"
)

type SipLeg struct {
	SrcIp string
	DestIp string
	Entity *IpEntity
	Dialog map[string] *DMessage
}

type IpEntity struct {
	MyIp string
	IsProxy bool
	Calls map[string][]*SipLeg
	Query chan SxsQuery
	//Contacts []string
}

type Elements func ([]*SipLeg)(string,bool)

var (
	attribute map[string]Elements
	)

func init() {
	attribute = make(map[string]Elements)
	attribute["callid"]=getCallId
	attribute["entity"]=getEntity
}

func NewSipEntity(Ip string, msg DMessage) chan SxsQuery {
	newEntity := IpEntity{MyIp: Ip, Calls:make(map[string][]*SipLeg), Query: make(chan SxsQuery)}
	go newEntity.Run()
	return newEntity.Query
}

func getCallId(c []*SipLeg) (string,bool) {
	if len(c)>0 && len(c[0].Dialog)>0 {
		l:= c[0].Dialog
		for _,x := range l {
			return x.SipMsg.CallId,false
		}
		return "",false
	}
	return "",false
}

func getEntity(c []*SipLeg) (string,bool){
	for _,l := range c {
		return l.Entity.MyIp,true
	}
	return "",false
}

func (i *IpEntity)Run(){
	MainWait.Add(1)
	for {
		qcode := <- i.Query
		if qcode.Cmd==0 {
			break
		}
		if(qcode.Cmd==commands["outgoing"]){
			msg,ok := qcode.Udata.(DMessage)
			if ok {
				i.sentMsg(&msg)
			}
			continue
		}
		if(qcode.Cmd==commands["incoming"]){
			msg,ok := qcode.Udata.(DMessage)
			if ok {
				i.receivedMsg(&msg)
			}
			continue
		}
		if(qcode.Cmd==commands["list"]){
			results:=make([]string,len(i.Calls))
			j:=0
			final:=false
			for _,l:= range i.Calls {
				results[j],final = attribute[qcode.Attribute](l)
				if final {
					break
				}
				j=j+1
			}
			response := qcode.CreateResponse()
			response.Udata=results
			response.Target=i.MyIp
			Output<-response
			continue
		}
	}
	MainWait.Done()
}

func (i *IpEntity)sentMsg(msg *DMessage) {
	if legs,ok:=i.Calls[msg.SipMsg.CallId]; !ok {
		i.Calls[msg.SipMsg.CallId] = make([]*SipLeg,1)
		i.Calls[msg.SipMsg.CallId][0] = i.NewSipLeg(msg)
	} else {
		found:=false
		for _,leg := range legs {
			if leg.DestIp==msg.DestIp() {
				leg.addMsg(msg)
				found=true
				break
			}
		}
		if !found {
			newLeg := i.NewSipLeg(msg)
			i.Calls[msg.SipMsg.CallId] = append(legs,newLeg)
		}
	}
}

func (i *IpEntity)receivedMsg(msg *DMessage) {
	if legs,ok:=i.Calls[msg.SipMsg.CallId]; !ok {
		i.Calls[msg.SipMsg.CallId] = make([]*SipLeg,1)
		i.Calls[msg.SipMsg.CallId][0] = i.NewSipLeg(msg)
	} else {
		found:=false
		for _,leg := range legs {
			if leg.SrcIp==msg.SrcIp() {
				leg.addMsg(msg)
				found=true
				break
			}
		}
		if !found {
			newLeg := i.NewSipLeg(msg)
			i.Calls[msg.SipMsg.CallId] = append(legs,newLeg)
		}
	}
}

func (i *IpEntity)NewSipLeg(msg *DMessage) *SipLeg {
	leg:=&SipLeg{Dialog:make(map[string]*DMessage),Entity:i}
	leg.addMsg(msg)
	return leg
}

func (i *SipLeg)addMsg(msg *DMessage) {
	if _,ok:=i.Dialog[msg.SipMsg.Cseq.Val]; !ok {
		i.Dialog[msg.SipMsg.Cseq.Val] = msg
	}
	// else the message is a resend
}