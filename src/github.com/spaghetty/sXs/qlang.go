package sxs

import (
	//"log"
	"time"
	"strconv"
	"strings"
	"math/rand"
)

// 1-10 system signaling
// 11-... query msg
// 11 - list

var (
	commands map[string]int
)

type SxsQuery struct {
	Uid string
	Target string
	Cmd int
	Expected int
	Attribute string
	Udata interface{}
	
}

type SxsResult struct {
	cmd int
}

func init() {
	commands = map[string]int{
		"term":0,
		"incoming":5,
		"outgoing":6,
		"list":100,
	}
}

func NewSxsQuery(q string) (SxsQuery,bool) {
	t := time.Now()
	uids := strconv.FormatInt(t.UnixNano(),16)
	uids = uids + strconv.Itoa(rand.Int())
	l := strings.Split(q," ")
	target := l[0]
	cmd,ok := commands[l[1]]
	if !ok {
		return SxsQuery{},false
	}
	attribute:=""
	if len(l) > 2 {
		attribute=l[2]
	}
	return SxsQuery{Uid:uids,Target:target,Cmd:cmd,Attribute:attribute},true
}

func (q *SxsQuery)CreateResponse() (res SxsQuery) {
	res.Uid=q.Uid
	res.Target=q.Target
	res.Cmd=-1
	res.Attribute=q.Attribute
	res.Expected=q.Expected
	return
} 