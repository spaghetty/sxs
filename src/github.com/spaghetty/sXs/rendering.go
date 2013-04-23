package sxs

import (
	"log"
)

type ResultSet struct {
	Request *SxsQuery
	Responses []*SxsQuery
}

type FormatReply func(*ResultSet)

type OutputHandler struct {
	PendingCommands map[string]ResultSet
}

var (
	Output chan SxsQuery
	Functions map[int]FormatReply
)

func init() {
	Functions = make(map[int] FormatReply)
	Functions[commands["list"]]=list
}

func list(r *ResultSet) {
	Rendering.Add(1)
	log.Println("merda funziona veramente:",len(r.Responses))
	res:=make(map[string]int)
	for _,q := range r.Responses {
		list:= q.Udata.([]string)
		//log.Println("I'm", q.Target, "and my callid are following:")
		for _,i := range list {
			if _,ok:=res[i];!ok {
				res[i]=0
			}
		}
	}
	for k,_ := range res {
		log.Println(k)
	}
	Rendering.Done()
}

func NewOutputHandler() *OutputHandler {
	return &OutputHandler{PendingCommands:make(map[string]ResultSet)}
}

func (oh *OutputHandler)Run() {
	Rendering.Add(1)
	for {
		q := <- Output
		log.Println(q)
		if q.Cmd==-1 {
			if val,ok:=oh.PendingCommands[q.Uid]; ok {
				val.Responses=append(val.Responses,&q)
				oh.PendingCommands[q.Uid]=val
				if len(val.Responses)==q.Expected {
					//we have done with this request
					r := oh.PendingCommands[q.Uid]
					go Functions[r.Request.Cmd](&r)
				}
			}
			continue
		}
		if q.Cmd==0 {
			break
		}
		if q.Cmd>0 {
			oh.PendingCommands[q.Uid]=ResultSet{Request:&q,Responses:make([]*SxsQuery,0,q.Expected)}
		}

	}
	Rendering.Done()
}

