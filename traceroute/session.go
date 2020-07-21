package traceroute

import (
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"sync"
	"time"
	"sync/atomic"
)

type Session struct {
	t  *Tracer
	ip net.IP
	ch chan *Reply

	mu      sync.RWMutex
	probes  []*packet
	route   []Reply
	retries int
}

type Reply struct {
	IP   net.IP
	RTT  time.Duration
	Hops int
}

type packet struct {
	IP   net.IP
	ID   uint32
	TTL  int
	Time time.Time
}

func newSession(t *Tracer, ip net.IP) *Session {
	s := &Session{
		t:       t,
		ip:      ip,
		ch:      make(chan *Reply, 64),
		retries: 0,
	}
	t.addSession(s)
	return s
}

func (s *Session) Ping(ttl int) error {
	req, err := s.t.sendRequest(s.ip, ttl)
	//req, err := s.t.sendUDPRequest(s.ip, 33434, ttl)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.probes = append(s.probes, req)
	s.mu.Unlock()
	return nil
}

func (s *Session) Receive() <-chan *Reply {
	return s.ch
}

func (s *Session) isDone(ttl int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, probe := range s.probes {
		if probe.TTL <= ttl {
			return false
		}
	}
	return true
}

func (s *Session) handle(reply *packet) {
	n := 0
	var req *packet

	s.mu.Lock()
	for _, probe := range s.probes {
		if probe.ID == reply.ID {
			req = probe
			continue
		}
		s.probes[n] = probe
		n++
	}
	s.probes = s.probes[:n]
	s.mu.Unlock()

	if req == nil {
		return
	}

	hops := req.TTL
	select {
	case s.ch <- &Reply{
		IP:   reply.IP,
		RTT:  reply.Time.Sub(req.Time),
		Hops: hops,
	}:
	default:
	}
}

func (s *Session) printProbes() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, probe := range s.probes {
		fmt.Println(*probe)
	}
	fmt.Println("---------------")
}

func (s *Session) retryProbes() error {
	s.mu.Lock()
	atomic.AddInt32(s.t.RetriesPerformed, int32(len(s.probes)))
	probes := s.probes[:]
	s.probes = []*packet{}
	s.mu.Unlock()
	for _, probe := range probes {
		err := s.Ping(probe.TTL)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) Close() {
	s.t.removeSession(s)
}

func shortIP(ip net.IP) net.IP {
	if v := ip.To4(); v != nil {
		return v
	}
	return ip
}

func newPacket(id uint32, dst net.IP, ttl int) []byte {
	// TODO: reuse buffers...
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:  int(id),
			Seq: int(id),
		},
	}
	p, _ := msg.Marshal(nil)
	ip := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(p),
		TOS:      16,
		ID:       int(id),
		Dst:      dst,
		Protocol: ProtocolICMP,
		TTL:      ttl,
	}
	buf, err := ip.Marshal()
	if err != nil {
		return nil
	}
	return append(buf, p...)
}

func newUDPPacket(id uint32, dst net.IP, ttl int) []byte {
	msg := []byte("random")
	ip := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(msg),
		TOS:      16,
		ID:       int(id),
		Dst:      dst,
		Protocol: ProtocolUDP,
		TTL:      ttl,
	}
	buf, err := ip.Marshal()
	if err != nil {
		return nil
	}
	return append(buf, msg...)
}

func getReplyData(msg *icmp.Message) []byte {
	switch b := msg.Body.(type) {
	case *icmp.TimeExceeded:
		return b.Data
	case *icmp.DstUnreach:
		return b.Data
	case *icmp.ParamProb:
		return b.Data
	}
	return nil
}
