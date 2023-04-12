package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortState uint8

const (
	CLOSE PortState = iota
	OPEN
)

type Scanner interface {
	Scan() map[uint16]PortState
}

type tcpScanner struct {
	mux       sync.Mutex
	firstPort uint16
	lastPort  uint16
	addr      string
	timeout   time.Duration
	batchSize int
}

func NewTcpScanner(first uint16, last uint16, addr string, timeout int, batchSize int) Scanner {
	sc := new(tcpScanner)
	sc.firstPort = first
	sc.lastPort = last
	sc.addr = addr
	sc.batchSize = batchSize
	sc.timeout = time.Duration(timeout) * time.Second
	return sc
}

func (s *tcpScanner) Scan() map[uint16]PortState {
	res := make(map[uint16]PortState)
	var wg sync.WaitGroup
	portRange := int(s.lastPort) - int(s.firstPort) + 1
	batchSize := s.batchSize
	batchCount := (portRange / batchSize) + 1
	for i := 1; i < int(batchCount)+1; i++ {
		if batchSize > portRange-batchSize*(i-1) {
			batchSize = portRange - batchSize*(i-1)
			batchCount = 1
		}
		wg.Add(batchSize)
		for j := batchSize*(i-1) + int(s.firstPort); j < batchSize*(i-1)+int(s.firstPort)+batchSize; j++ {
			go func(port uint16) {
				defer wg.Done()
				addr := fmt.Sprintf("%s:%d", s.addr, port)
				conn, err := net.DialTimeout("tcp", addr, s.timeout)
				if err != nil {
					s.mux.Lock()
					res[port] = CLOSE
					s.mux.Unlock()
					return
				}
				defer conn.Close()
				s.mux.Lock()
				res[port] = OPEN
				s.mux.Unlock()
			}(uint16(j))
		}
		wg.Wait()
	}
	return res
}

type PortPrinter interface {
	PrintPorts(ports map[uint16]PortState)
}

type textPortPrinter struct {
	showAll bool
}

func NewTextPortPrinter(showAll bool) PortPrinter {
	p := new(textPortPrinter)
	p.showAll = showAll
	return p
}

func (p *textPortPrinter) PrintPorts(ports map[uint16]PortState) {
	for k, v := range ports {
		if v == OPEN {
			fmt.Printf("%d - OPEN\n", k)
			continue
		}
		if p.showAll {
			fmt.Printf("%d - CLOSE\n", k)
		}
	}
}

type jsonPortPrinter struct {
	showAll bool
}

func NewJsonPortPrinter(showAll bool) PortPrinter {
	p := new(jsonPortPrinter)
	p.showAll = showAll
	return p
}

func (p *jsonPortPrinter) PrintPorts(ports map[uint16]PortState) {
	prts := make(map[uint16]string)
	for k, v := range ports {
		if v == OPEN {
			prts[k] = "OPEN"
			continue
		}
		if p.showAll {
			prts[k] = "CLOSE"
		}
	}
	json.NewEncoder(os.Stdout).Encode(prts)
}

func main() {
	showall := flag.Bool("all", false, "the program will print both open and close ports")
	jsonflag := flag.Bool("json", false, "the program will serialize result in json and print it to stdout")
	addr := flag.String("addr", "scanme.nmap.org", "target address")
	rngflag := flag.String("ports", "0-1023", "port scanning range (e.g. 80, 0-1023, 5000-6000)")
	timeoutflag := flag.Int("timeout", 75, "time (in seconds) after processing connection will be terminated")
	batchflag := flag.Int("batch", 2000, "number of ports that will be scanning at one time")
	flag.Parse()
	rng := strings.Split(*rngflag, "-")
	first, err := strconv.Atoi(rng[0])
	if err != nil {
		fmt.Println("Wrong range syntax.")
		os.Exit(1)
	}
	var last int
	if len(rng) == 1 {
		last = first
		*showall = true
	} else {
		last, err = strconv.Atoi(rng[1])
		if err != nil {
			fmt.Println("Wrong range syntax.")
			os.Exit(1)
		}
	}
	if last < first || last > 65535 || first > 65535 {
		fmt.Println("Wrong range syntax. Notice that port minimal value is 0 and maximum is 65535.")
		return
	}
	starttime := time.Now().Unix()
	var printer PortPrinter
	if *jsonflag {
		printer = NewJsonPortPrinter(*showall)
	} else {
		fmt.Printf("Scanning %s with range %s\n", *addr, *rngflag)
		fmt.Printf("batch size: %d; timeout: %d sec\n", *batchflag, *timeoutflag)
		printer = NewTextPortPrinter(*showall)
	}
	scanner := NewTcpScanner(uint16(first), uint16(last), *addr, *timeoutflag, *batchflag)
	ports := scanner.Scan()
	printer.PrintPorts(ports)
	if !(*jsonflag) {
		fmt.Printf("\nScanned in %d seconds (^_^)\n", time.Now().Unix()-starttime)
	}
}
