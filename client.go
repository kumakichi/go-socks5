package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

const (
	authOK           = uint8(0x00)
	authNegotiateVer = uint8(0x01)
	socks5Version    = uint8(0x05)
	authNone         = uint8(0x00)
	authUsrPwd       = uint8(0x02)
	noAcceptableAuth = uint8(0xFF)
	cmdConnect       = uint8(0x01)
	cmdBind          = uint8(0x02)
	cmdUdpAssociate  = uint8(0x03)
	atypIPV4         = uint8(0x01)
	atypDomain       = uint8(0x03)
	atypIPV6         = uint8(0x04)
	reqOK            = uint8(0x00)
)

type bndAddr struct {
	ip   net.IP
	port int
}

func main() {
	address := ":1080"
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Printf("error dial : %s\n", err.Error())
		os.Exit(-1)
	}
	defer conn.Close()

	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	if ok := sendMethodNegotiate(conn); ok != true {
		return
	}

	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	method, ok := parseMethodNegotiateResult(conn)
	if !ok {
		return
	}
	switch method { // only support authUsrPwd/authNone currently
	case authNone:
		break
	case authUsrPwd:
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		if ok := usrPwdNegotiate(conn); ok != true {
			return
		}
		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+
		if ok := usrPwdNegotiateResult(conn); ok != true {
			return
		}
	default:
		fmt.Printf("Unsupported method : %0x\n", method)
		return
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// only support tcp CONNECT currently
	if ok := sendRequest(conn); ok != true {
		return
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	addr, ok := parseReqResult(conn)
	if ok != true {
		return
	}
	fmt.Printf("server bind address is %s:%d\n", addr.ip.String(), addr.port)

	conn.Write([]byte("GET / HTTP/1.1\r\nHost:www.bing.com\r\n\r\n"))

	buff := make([]byte, 4096)
	n, _ := conn.Read(buff)
	fmt.Printf(string(buff[:n]))
}

func sendMethodNegotiate(conn net.Conn) bool {
	buff := make([]byte, 3)
	buff[0] = socks5Version
	buff[1] = 1
	buff[2] = authUsrPwd
	_, err := conn.Write(buff)
	if err != nil {
		fmt.Printf("error sendMethodNegotiate : %s\n", err.Error())
		return false
	}
	return true
}

func parseMethodNegotiateResult(conn net.Conn) (uint8, bool) {
	buff := make([]byte, 2)
	_, err := io.ReadAtLeast(conn, buff, 2)
	if err != nil {
		fmt.Printf("error parseMethodNegotiateResult : %s\n", err.Error())
		return noAcceptableAuth, false
	}

	// validate ver
	if buff[0] != socks5Version {
		fmt.Printf("Unsupported socks version:%0x\n", buff[0])
		return noAcceptableAuth, false
	}

	return buff[1], true
}

func sendRequest(conn net.Conn) bool {
	addr := "www.bing.com"
	port := uint16(80)

	ver := socks5Version
	cmd := cmdConnect
	rsv := byte(0x00)
	atyp := atypDomain

	addLen := len(addr)
	dstAddr := make([]byte, addLen+1)
	dstAddr[0] = byte(addLen)
	copy(dstAddr[1:], []byte(addr))

	// net byte order(big endian)
	dstPort := make([]byte, 2)
	dstPort[0] = byte(port >> 8)
	dstPort[1] = byte(port & 0xff)

	buff := []byte{ver, cmd, rsv, atyp}
	buff = append(buff, dstAddr...)
	buff = append(buff, dstPort...)
	_, err := conn.Write(buff)
	if err != nil {
		fmt.Printf("error send request:%s\n", err.Error())
		return false
	}
	return true
}

func parseReqResult(conn net.Conn) (*bndAddr, bool) {
	buff := make([]byte, 4)
	_, err := io.ReadAtLeast(conn, buff, 4)
	if err != nil {
		fmt.Printf("read req result error:%s\n", err.Error())
		return nil, false
	}

	// validate ver
	if buff[0] != socks5Version {
		fmt.Printf("invalid socks version : %0x\n", buff[0])
		return nil, false
	}
	// rep
	if buff[1] != reqOK {
		fmt.Printf("invalid rep:%0x\n", buff[1]) // TODO: parse rep number to corresponding msg
		return nil, false
	}
	// atyp
	atyp := buff[3]

	var ip net.IP

	switch atyp {
	case atypIPV4:
		buff := make([]byte, 4)
		_, err := io.ReadAtLeast(conn, buff, 4)
		if err != nil {
			fmt.Printf("error read atypIPV4 : %s\n", err.Error())
			return nil, false
		}
		ip = net.IP(buff)
	case atypIPV6:
		buff := make([]byte, 16)
		_, err := io.ReadAtLeast(conn, buff, 16)
		if err != nil {
			fmt.Printf("error read atypIPV6 : %s\n", err.Error())
			return nil, false
		}
		ip = net.IP(buff)
	default:
		fmt.Printf("Unsupported atyp : %0x\n", atyp)
		return nil, false
	}

	p := make([]byte, 2)
	_, err = io.ReadAtLeast(conn, p, 2)
	if err != nil {
		fmt.Printf("error read port : %s\n", err.Error())
		return nil, false
	}
	port := int(p[0])<<8 + int(p[1])
	return &bndAddr{ip: ip, port: port}, true
}

func usrPwdNegotiate(conn net.Conn) bool {
	usr := "sans"
	pwd := "sans"

	ver := authNegotiateVer
	ulen := uint8(len(usr))
	plen := uint8(len(pwd))

	buff := []byte{ver, ulen}
	buff = append(buff, []byte(usr)...)
	buff = append(buff, plen)
	buff = append(buff, []byte(pwd)...)
	_, err := conn.Write(buff)
	if err != nil {
		fmt.Printf("error send usr/pwd : %s\n", err.Error())
		return false
	}
	return true
}

func usrPwdNegotiateResult(conn net.Conn) bool {
	buff := make([]byte, 2)
	_, err := io.ReadAtLeast(conn, buff, 2)
	if err != nil {
		fmt.Printf("error read usr/pwd negotiate result : %s\n", err.Error())
		return false
	}

	// validate ver
	if buff[0] != authNegotiateVer {
		fmt.Printf("invalid auth negotiate version : %0x\n", buff[0])
		return false
	}

	// auth result
	if buff[1] != authOK {
		fmt.Println("auth failed:")
		return false
	}
	return true
}
