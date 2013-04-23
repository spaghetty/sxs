package main

import (
	"os"
	"log"
	"flag"
	"sync"
	"bytes"
	"strings"
	"github.com/spaghetty/sXs"
	"github.com/nsf/termbox-go"
	"github.com/akrennmair/gopcap"
)

var GuiWait sync.WaitGroup

type SxsConfig struct {
	Test string
	Filter string
	Args []string
}

type SxsGui struct {
        Head bytes.Buffer
        Status bytes.Buffer
        quitflag  bool
        termbox_event chan termbox.Event
}

func newSxsGui() *SxsGui {
        tmp:=new(SxsGui)
        tmp.quitflag=false
        return tmp
}

func render_line(line *bytes.Reader, h int) {
        m_x,_:= termbox.Size()
        for x:=0; x<=m_x; x++ {
                if r,_,err:=line.ReadRune(); err==nil {
                        termbox.SetCell(x,h,r,termbox.ColorBlack, termbox.ColorWhite);
                } else {
                        termbox.SetCell(x,h,' ',termbox.ColorBlack, termbox.ColorWhite);
                }
        }
}

func (g *SxsGui) draw_head() {
        render_line(bytes.NewReader(g.Head.Bytes()),0)
}

func (g *SxsGui) draw_status() {
        _,m_y:=termbox.Size()
        render_line(bytes.NewReader(g.Status.Bytes()),m_y-2)
}

func (g *SxsGui) draw() {
        termbox.Clear(termbox.ColorDefault, termbox.ColorDefault)
	g.draw_head()
        termbox.SetCell(5,5, 'M', termbox.ColorBlack, termbox.ColorWhite);
        termbox.SetCell(6,6, 'X', termbox.ColorBlack, termbox.ColorWhite);
        g.draw_status()
        termbox.Flush()
}

func (g *SxsGui) main_loop() {
	GuiWait.Add(1)
        g.termbox_event = make(chan termbox.Event, 20)
        go func() {
                for {
                        g.termbox_event <- termbox.PollEvent()
                }
        }()
        for {
                select {
                case ev := <-g.termbox_event:
                        ok := g.handle_event(&ev)
                        if !ok {
				GuiWait.Done()
                                return
                        }
                        g.consume_more_events()
                        g.draw()
                        termbox.Flush()
                }
        }
}

func (g *SxsGui) consume_more_events() bool {
        for {
                select {
                case ev := <-g.termbox_event:
                        ok := g.handle_event(&ev)
                        if !ok {
                                return false
                        }
                default:
                        return true
                }
        }
        panic("unreachable")
}

func (g *SxsGui) on_key(ev *termbox.Event) {
        switch ev.Key {
        case termbox.KeyCtrlQ:
                g.quitflag=true
        }
}

func (g *SxsGui) handle_event(ev *termbox.Event) bool {
        switch ev.Type {
        case termbox.EventKey:
                g.on_key(ev)
                //g.on_sys_key(ev)
                if g.quitflag {
                        return false
                }
        case termbox.EventError:
                panic(ev.Err)
        }
        return true
}

func parse_flags(cfg *SxsConfig) {
	flag.StringVar(&(cfg.Filter),"filter","port 5060 || port 5080","value for server SIP port")
	flag.Parse()
	if flag.NArg()>0 {
		cfg.Args = append(cfg.Args, flag.Args()...)
	}
}

func check_args(cfg *SxsConfig) bool {
	for _,f := range cfg.Args {
		if _,err := os.Stat(f); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func is_sip(pkt string) bool {
	return (strings.HasPrefix(pkt,"SIP") ||
		strings.HasPrefix(pkt,"INVITE") ||
		strings.HasPrefix(pkt,"ACK") ||
		strings.HasPrefix(pkt,"CANCEL") ||
		strings.HasPrefix(pkt,"BYE") ||
		strings.HasPrefix(pkt,"OPTION") ||
		strings.HasPrefix(pkt,"REFER") ||
		strings.HasPrefix(pkt,"UPDATE"))
}



func main() {
	cfg := SxsConfig{}
	parse_flags(&cfg)
	if len(cfg.Args)>0 {
		if !check_args(&cfg) {
			log.Fatal("Troubles with files")
		}
	}
	mainEngine := sxs.NewEngine()
	go mainEngine.Run()
        err := termbox.Init()
        if err != nil {
                log.Println("error termbox init")
                panic(err)
        }
        defer termbox.Close()

        termbox.SetInputMode(termbox.InputAlt)
        mainGui := newSxsGui()
        mainGui.Head.WriteString("sXs 0.0.1 [ applied filter:" + cfg.Filter + " ]")
        mainGui.Status.WriteString("[status] ")
        mainGui.draw()
        mainGui.main_loop()
        termbox.Flush()
        termbox.Clear(termbox.ColorDefault, termbox.ColorDefault)
	for _,f := range cfg.Args {
		h,err:=pcap.Openoffline(f)
		if err!= nil {
			log.Fatal("error opening pcap file:",f)
		}
		defer h.Close()
		log.Println(cfg.Filter)
		h.Setfilter(cfg.Filter)
		for pkt, errint := h.NextEx(); errint>0; pkt, errint= h.NextEx() {
			if pkt==nil {
				log.Println("no such package")
			}
			pkt.Decode()
			var srcPort, dstPort uint16 = 0,0
			if pkt.TCP!=nil {
				srcPort = pkt.TCP.SrcPort
			 	dstPort = pkt.TCP.DestPort
			} 
			if pkt.UDP!=nil {
				srcPort = pkt.UDP.SrcPort
				dstPort = pkt.UDP.DestPort
			}
			if srcPort!=0 && dstPort!=0 && pkt.Payload!=nil && is_sip(string(pkt.Payload)) {
				mainEngine.SendMessage(sxs.DMessage{SrcIp:pkt.IP.SrcAddr(), DestIp:pkt.IP.DestAddr(),
				SrcPort: srcPort, DstPort: dstPort, Msg:string(pkt.Payload)})
			}
			//fmt.Printf("%s:%d-%d\n",pkt.IP.SrcAddr(),srcPort,dstPort)
		}
	}
	// mainEngine.SendQuery("* list callid")
	// mainEngine.SendQuery("* list entity")
	// mainEngine.SendQuery("* list callid")
	// mainEngine.SendQuery("* list callid")
	// mainEngine.SendQuery("* list callid")
	GuiWait.Wait()
	mainEngine.SendTerm()
}