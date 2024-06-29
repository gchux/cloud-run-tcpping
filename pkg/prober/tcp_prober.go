package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type (
	TCPProberTask struct {
		proberTask
		network string
		dialer  *net.Dialer
	}
)

var (
	// https://pkg.go.dev/syscall#Linger
	_SO_LINGER = &syscall.Linger{Onoff: 1, Linger: 0} // skip TIME_WAIT

	tlsConfig = &tls.Config{InsecureSkipVerify: true}
)

func setSocketOptions(fd uintptr, err *error) {
	// https://golang.google.cn/src/internal/poll/sockopt.go
	// https://pkg.go.dev/syscall#SetsockoptLinger
	lingerErr := syscall.SetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER, _SO_LINGER)
	*err = errors.Join(lingerErr)
}

func connectionControl(task *proberTask, network, address string, conn syscall.RawConn) error {
	var operr error
	if err := conn.Control(func(fd uintptr) {
		setSocketOptions(fd, &operr)
	}); err != nil {
		return err
	}
	return operr
}

func getTCPNetwork(task *proberTask) string {
	switch {
	default:
		return "tcp"
	case task.IPv4:
		return "tcp4"
	case task.IPv6:
		return "tcp6"
	}
}

func newTCPProberTask(task *proberTask) Prober {
	dialer := &net.Dialer{
		DualStack: false,
		Timeout:   task.Params.Timeout,
		Control: func(network, address string, conn syscall.RawConn) error {
			return connectionControl(task, network, address, conn)
		},
	}
	network := getTCPNetwork(task)
	return &TCPProberTask{*task, network, dialer}
}

func (p *TCPProberTask) probe(ctx context.Context, attempt *uint64) (*time.Duration, error) {
	target, err := p.beforeProbing(ctx, attempt)
	if err != nil {
		target = p.Target
	}

	timeout := p.Params.Timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	conn, err := p.dialer.DialContext(ctx, p.network, target.String())
	latency := time.Since(start)

	if err == nil {
		conn.Close()
	}

	p.afterProbing(ctx, attempt, target, &latency, err)

	return &latency, err
}
