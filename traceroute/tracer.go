package traceroute

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// IANA Assigned Internet Protocol Numbers
const (
	ProtocolICMP     = 1
	ProtocolTCP      = 6
	ProtocolUDP      = 17
	ProtocolIPv6ICMP = 58
)

var (
	errMessageTooShort     = errors.New("message too short")
	errUnsupportedProtocol = errors.New("unsupported protocol")
	errNoReplyData         = errors.New("no reply data")
)

type Tracer struct {
	Config

	once sync.Once
	conn *net.IPConn
	err  error

	mu      sync.RWMutex
	session map[string][]*Session
	seq     uint32

	Retries          int
	PingsPerformed   *int32
	PingsReceived    *int32
	RetriesPerformed *int32
}

type Config struct {
	Delay   time.Duration
	Timeout time.Duration
	MaxHops int
	Count   int
	Network string
	Addr    *net.IPAddr
}

func (t *Tracer) Trace(ctx context.Context, ip net.IP) ([]Reply, error) {
	session, err := t.NewSession(ip)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	delay := time.NewTicker(t.Delay)
	defer delay.Stop()

	max := t.MaxHops
	for ttl := 1; ttl <= t.MaxHops && ttl <= max; ttl++ {
		err = session.Ping(ttl)
		if err != nil {
			fmt.Println(err.Error())
			return nil, err
		}
		atomic.AddInt32(t.PingsPerformed, 1)

		select {
		case <-delay.C:
			continue
		case reply := <-session.ch:
			session.route = append(session.route, *reply)
			if max > reply.Hops && ip.Equal(reply.IP) {
				max = reply.Hops
			}
			atomic.AddInt32(t.PingsReceived, 1)
		case <-ctx.Done():
			return session.route, ctx.Err()
		}
	}

	if session.isDone(max) {
		//fmt.Println("1 - - - -", session.route)
		//session.printProbes()
		return session.route, nil
	}

	deadline := time.After(t.Timeout)
	for {
		select {
		case reply := <-session.ch:
			session.route = append(session.route, *reply)
			if max > reply.Hops && ip.Equal(reply.IP) {
				max = reply.Hops
			}
			atomic.AddInt32(t.PingsReceived, 1)
			if session.isDone(max) {
				//fmt.Println("2 - - - -", session.route)
				//session.printProbes()
				return session.route, nil
			}
		case <-deadline:
			//fmt.Println("3 - - - -", session.route)
			session.retries += 1
			if session.retries >= t.Retries {
				//fmt.Println("3 - - - -", session.route)
				//session.printProbes()
				return session.route, nil
			}
			err = session.retryProbes()
			if err != nil {
				return session.route, err
			}

			deadline = time.After(t.Timeout)
			//session.printProbes()
		case <-ctx.Done():
			return session.route, nil
		}
	}
}

func (t *Tracer) NewSession(ip net.IP) (*Session, error) {
	t.once.Do(t.init)
	if t.err != nil {
		return nil, t.err
	}
	return newSession(t, shortIP(ip)), nil
}

func (t *Tracer) init() {
	t.conn, t.err = t.listen(t.Network, t.Addr)
	if t.err != nil {
		return
	}
	go t.serve(t.conn)
	return
}

func (t *Tracer) listen(network string, laddr *net.IPAddr) (*net.IPConn, error) {
	conn, err := net.ListenIP(network, laddr)
	if err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = raw.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (t *Tracer) serve(conn *net.IPConn) error {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromIP(buf)
		if err != nil {
			return err
		}
		err = t.serveData(from.IP, buf[:n])
		if err != nil {
			fmt.Println(err.Error(), from.IP)
			continue
		}
	}
}

func (t *Tracer) serveData(from net.IP, b []byte) error {
	if from.To4() == nil {
		return errUnsupportedProtocol
	}
	now := time.Now()
	msg, err := icmp.ParseMessage(ProtocolICMP, b)
	if err != nil {
		return err
	}
	if msg.Type == ipv4.ICMPTypeEchoReply {
		echo := msg.Body.(*icmp.Echo)
		return t.serveReply(from, &packet{from, uint32(echo.ID), 1, now})
	}
	b = getReplyData(msg)
	if len(b) < ipv4.HeaderLen {
		return errMessageTooShort
	}
	switch b[0] >> 4 {
	case ipv4.Version:
		ip, err := ipv4.ParseHeader(b)
		if err != nil {
			return err
		}
		return t.serveReply(ip.Dst, &packet{from, uint32(ip.ID), ip.TTL, now})
	case ipv6.Version:
		ip, err := ipv6.ParseHeader(b)
		if err != nil {
			return err
		}
		return t.serveReply(ip.Dst, &packet{from, uint32(ip.FlowLabel), ip.HopLimit, now})
	default:
		return errUnsupportedProtocol
	}
}

func (t *Tracer) serveReply(dst net.IP, res *packet) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	a := t.session[string(shortIP(dst))]
	for _, s := range a {
		s.handle(res)
	}
	return nil
}

func (t *Tracer) sendRequest(dst net.IP, ttl int) (*packet, error) {
	id := atomic.AddUint32(&t.seq, 1)
	b := newPacket(id, dst, ttl)
	req := &packet{dst, id, ttl, time.Now()}
	_, err := t.conn.WriteToIP(b, &net.IPAddr{IP: dst})
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (t *Tracer) sendUDPRequest(dst net.IP, port int, ttl int) (*packet, error) {
	id := atomic.AddUint32(&t.seq, 1)
	b := newUDPPacket(id, dst, ttl)
	req := &packet{dst, id, ttl, time.Now()}

	destination := [4]byte{}
	copy(destination[:], dst.To4())

	sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
	defer syscall.Close(sendSocket)

	syscall.Sendto(sendSocket, b, 0, &syscall.SockaddrInet4{Port: port, Addr: destination})

	return req, nil
}

func (t *Tracer) addSession(s *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil {
		t.session = make(map[string][]*Session)
	}
	t.session[string(s.ip)] = append(t.session[string(s.ip)], s)
}

func (t *Tracer) removeSession(s *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.session[string(s.ip)]
	for i, it := range a {
		if it == s {
			t.session[string(s.ip)] = append(a[:i], a[i+1:]...)
			return
		}
	}
}

func (t *Tracer) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		t.conn.Close()
	}
}
