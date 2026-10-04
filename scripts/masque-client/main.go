// masque-interop-client is an intentionally independent RFC 9298 client.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	proxy := flag.String("proxy", "", "RFC 9298 proxy URI template")
	ipProxy := flag.String("ip-proxy", "", "RFC 9484 CONNECT-IP URI")
	proxyAddr := flag.String("proxy-address", "", "UDP address used to reach the proxy")
	target := flag.String("target", "", "UDP target as host:port")
	deniedTarget := flag.String("denied-target", "", "optional target expected to receive HTTP 403 on the shared connection")
	caFile := flag.String("ca", "", "PEM certificate trusted for the lab proxy")
	payload := flag.String("payload", "masque-independent-client", "UDP payload")
	expectStatus := flag.Int("expect-status", 200, "expected HTTP response status")
	sessions := flag.Int("sessions", 1, "number of CONNECT-UDP sessions to multiplex on one HTTP/3 connection")
	capsuleFallback := flag.Bool("capsule-fallback", false, "disable QUIC DATAGRAM and test DATAGRAM capsules")
	connectIP := flag.Bool("connect-ip", false, "run the RFC 9484 CONNECT-IP test")
	flag.Parse()
	if *proxyAddr == "" || *caFile == "" || (!*connectIP && (*proxy == "" || *target == "")) || (*connectIP && *ipProxy == "") {
		flag.Usage()
		os.Exit(2)
	}

	caPEM, err := os.ReadFile(*caFile)
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		must(fmt.Errorf("CA file contains no certificate"))
	}
	tlsConfig := &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}
	if *connectIP {
		must(runConnectIP(*ipProxy, *proxyAddr, *expectStatus, tlsConfig))
		return
	}
	if *capsuleFallback {
		must(runCapsuleFallback(*proxy, *proxyAddr, *target, *payload, tlsConfig))
		return
	}
	transport := masque.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
		},
		DialAddr: func(ctx context.Context, _ string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, *proxyAddr, tlsConf, quicConf)
		},
	}
	if *sessions < 1 {
		must(fmt.Errorf("sessions must be at least 1"))
	}
	if *expectStatus != 200 {
		request, err := masque.NewRequest(
			context.Background(),
			uritemplate.MustNew(*proxy),
			*target,
		)
		must(err)
		_, response, err := transport.Dial(request)
		if response == nil || response.StatusCode != *expectStatus {
			must(fmt.Errorf("expected HTTP %d, response=%v, error=%v", *expectStatus, response, err))
		}
		fmt.Printf("PASS rejected unauthorized target with HTTP %d\n", response.StatusCode)
		return
	}

	quicConn, err := quic.DialAddr(context.Background(), *proxyAddr, tlsConfig, transport.QUICConfig)
	must(err)
	defer quicConn.CloseWithError(0, "")
	clientConn, err := transport.NewClientConn(quicConn)
	must(err)
	connections := make([]*masque.Conn, 0, *sessions)
	for i := 0; i < *sessions; i++ {
		request, err := masque.NewRequest(context.Background(), uritemplate.MustNew(*proxy), *target)
		must(err)
		conn, response, err := clientConn.Dial(request)
		must(err)
		if response.StatusCode != *expectStatus {
			must(fmt.Errorf("expected HTTP %d, got %d", *expectStatus, response.StatusCode))
		}
		connections = append(connections, conn)
		defer conn.Close()
		fmt.Printf("opened CONNECT-UDP session %d/%d\n", i+1, *sessions)
	}
	if *deniedTarget != "" {
		request, err := masque.NewRequest(
			context.Background(),
			uritemplate.MustNew(*proxy),
			*deniedTarget,
		)
		must(err)
		_, response, err := clientConn.Dial(request)
		if response == nil || response.StatusCode != 403 || err == nil {
			must(fmt.Errorf("expected shared-connection HTTP 403, response=%v, error=%v", response, err))
		}
		fmt.Println("rejected unauthorized stream with HTTP 403 without closing the HTTP/3 connection")
	}
	for i, conn := range connections {
		must(conn.SetDeadline(time.Now().Add(5 * time.Second)))
		message := []byte(*payload)
		if *sessions > 1 {
			message = []byte(fmt.Sprintf("%s-%d", *payload, i))
		}
		_, err = conn.WriteTo(message, nil)
		must(err)
		reply := make([]byte, 64*1024)
		n, _, err := conn.ReadFrom(reply)
		must(err)
		want := append([]byte("udp:"), message...)
		if string(reply[:n]) != string(want) {
			must(fmt.Errorf("unexpected reply %q, want %q", reply[:n], want))
		}
		fmt.Printf("round trip completed on session %d/%d\n", i+1, *sessions)
	}
	fmt.Printf("PASS %d independent masque-go sessions multiplexed on one HTTP/3 connection\n", *sessions)
}

func runConnectIP(proxyURL, proxyAddr string, expectStatus int, tlsConfig *tls.Config) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, proxyURL, nil)
	if err != nil {
		return err
	}
	req.Proto = "connect-ip"
	req.Host = req.URL.Host
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	quicConn, err := quic.DialAddr(context.Background(), proxyAddr, tlsConfig, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return err
	}
	defer quicConn.CloseWithError(0, "")
	clientConn := (&http3.Transport{EnableDatagrams: true}).NewClientConn(quicConn)
	stream, err := clientConn.OpenRequestStream(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := stream.SendRequestHeader(req); err != nil {
		return err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return err
	}
	if response.StatusCode != expectStatus {
		return fmt.Errorf("CONNECT-IP rejected: status=%d headers=%v", response.StatusCode, response.Header)
	}
	if expectStatus != http.StatusOK {
		fmt.Printf("PASS rejected unauthorized CONNECT-IP target with HTTP %d\n", response.StatusCode)
		return nil
	}
	if response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		return fmt.Errorf("CONNECT-IP response omitted capsule negotiation: headers=%v", response.Header)
	}
	// Request ID 1, IPv4, wildcard address, host prefix.
	if _, err := stream.Write([]byte{2, 7, 1, 4, 0, 0, 0, 0, 32}); err != nil {
		return err
	}
	kind, assignment, err := readCapsule(stream)
	if err != nil || kind != 1 || string(assignment) != string([]byte{1, 4, 10, 20, 0, 2, 32}) {
		return fmt.Errorf("invalid ADDRESS_ASSIGN: type=%d payload=%x error=%v", kind, assignment, err)
	}
	kind, route, err := readCapsule(stream)
	if err != nil || kind != 3 || string(route) != string([]byte{4, 10, 30, 0, 9, 10, 30, 0, 9, 0}) {
		return fmt.Errorf("invalid initial ROUTE_ADVERTISEMENT: type=%d payload=%x error=%v", kind, route, err)
	}
	kind, withdrawal, err := readCapsule(stream)
	if err != nil || kind != 3 || len(withdrawal) != 0 {
		return fmt.Errorf("invalid route withdrawal: type=%d payload=%x error=%v", kind, withdrawal, err)
	}
	kind, restored, err := readCapsule(stream)
	if err != nil || kind != 3 || string(restored) != string(route) {
		return fmt.Errorf("invalid restored route: type=%d payload=%x error=%v", kind, restored, err)
	}
	packet := ipv4Packet([4]byte{10, 20, 0, 2}, [4]byte{10, 30, 0, 9})
	if err := stream.SendDatagram(append([]byte{0}, packet...)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := stream.ReceiveDatagram(ctx)
	if err != nil {
		return err
	}
	want := ipv4Packet([4]byte{10, 30, 0, 9}, [4]byte{10, 20, 0, 2})
	if len(reply) != len(want)+1 || reply[0] != 0 || string(reply[1:]) != string(want) {
		return fmt.Errorf("unexpected CONNECT-IP reply: %x", reply)
	}
	fmt.Println("PASS RFC 9484 CONNECT-IP assignment, route withdrawal/restoration, and IP packet round trip")
	return nil
}

func readCapsule(reader io.Reader) (uint64, []byte, error) {
	kind, err := readVarint(reader)
	if err != nil {
		return 0, nil, err
	}
	length, err := readVarint(reader)
	if err != nil {
		return 0, nil, err
	}
	if length > 64*1024 {
		return 0, nil, fmt.Errorf("capsule too large: %d", length)
	}
	payload := make([]byte, int(length))
	_, err = io.ReadFull(reader, payload)
	return kind, payload, err
}

func readVarint(reader io.Reader) (uint64, error) {
	var encoded [8]byte
	if _, err := io.ReadFull(reader, encoded[:1]); err != nil {
		return 0, err
	}
	width := 1 << (encoded[0] >> 6)
	if _, err := io.ReadFull(reader, encoded[1:width]); err != nil {
		return 0, err
	}
	value := uint64(encoded[0] & 0x3f)
	for _, b := range encoded[1:width] {
		value = value<<8 | uint64(b)
	}
	return value, nil
}

func ipv4Packet(source, destination [4]byte) []byte {
	packet := make([]byte, 64)
	packet[0] = 0x45
	packet[2], packet[3] = 0, byte(len(packet))
	packet[8], packet[9] = 64, 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	packet[10], packet[11] = byte(checksum>>8), byte(checksum)
	copy(packet[20:], []byte("datum-connect-ip-e2e"))
	return packet
}

func runCapsuleFallback(proxy, proxyAddr, target, payload string, tlsConfig *tls.Config) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	proxyURL, err := uritemplate.MustNew(proxy).Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(port),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, proxyURL, nil)
	if err != nil {
		return err
	}
	req.Proto = "connect-udp"
	req.Host = req.URL.Host
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")

	quicConn, err := quic.DialAddr(context.Background(), proxyAddr, tlsConfig, &quic.Config{})
	if err != nil {
		return err
	}
	defer quicConn.CloseWithError(0, "")
	clientConn := (&http3.Transport{}).NewClientConn(quicConn)
	stream, err := clientConn.OpenRequestStream(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := stream.SendRequestHeader(req); err != nil {
		return err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		return fmt.Errorf("capsule fallback rejected: status=%d headers=%v", response.StatusCode, response.Header)
	}
	if len(payload)+1 >= 64 {
		return fmt.Errorf("fallback test payload is too large for its compact test encoder")
	}
	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	capsule := append([]byte{0, byte(len(payload) + 1), 0}, []byte(payload)...)
	if _, err := stream.Write(capsule); err != nil {
		return err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(stream, header); err != nil {
		return err
	}
	if header[0] != 0 || header[1] == 0 || header[1] >= 64 {
		return fmt.Errorf("unexpected DATAGRAM capsule header %x", header)
	}
	body := make([]byte, int(header[1]))
	if _, err := io.ReadFull(stream, body); err != nil {
		return err
	}
	want := "udp:" + payload
	if body[0] != 0 || string(body[1:]) != want {
		return fmt.Errorf("unexpected DATAGRAM capsule payload %q, want %q", body, want)
	}
	fmt.Printf("PASS DATAGRAM capsule fallback round trip: %q\n", body[1:])
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var _ net.PacketConn = (*masque.Conn)(nil)
