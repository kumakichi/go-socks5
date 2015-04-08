package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

const (
	negotiationVer   = uint8(0x01)
	socks5Version    = uint8(0x05)
	authNone         = uint8(0x00)
	authUsrPwd       = uint8(0x02)
	noAcceptableAuth = uint8(0xFF)
	authOK           = uint8(0x00)
	authFail         = uint8(0x01)
	cmdConnect       = uint8(0x01)
	cmdBind          = uint8(0x02)
	cmdUdpAssociate  = uint8(0x03)
	atypIPV4         = uint8(0x01)
	atypDomain       = uint8(0x03)
	atypIPV6         = uint8(0x04)
)

const (
	cmdRepSucceeded = iota
	cmdRepGeneralFailure
	cmdRepConnectionNotAllowed
	cmdRepNetworkUnreachable
	cmdRepHostUnreachable
	cmdRepConnectionRefused
	cmdRepTTLExpired
	cmdRepCommandNotSupported
	cmdRepAddressTypeNotSupported
)

func main() {
	// accept conn
	laddr := ":1080"
	listener, err := net.Listen("tcp", laddr)
	checkErr(err)
	fmt.Println("Listen at:", laddr)
	for {
		conn, err := listener.Accept()
		checkErr(err)
		go procClient(conn)
	}
}

func checkErr(e error) {
	if e != nil {
		fmt.Println(e.Error())
		os.Exit(-1)
	}
}

func procClient(conn net.Conn) {
	defer conn.Close()

	// request from client
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	// validate socks5 version
	ver := make([]uint8, 1)
	_, err := io.ReadAtLeast(conn, ver, 1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if ver[0] != socks5Version {
		fmt.Printf("Invalid socks5 version: %0x,should be %0x\n", ver[0], socks5Version)
		return
	}

	// auth
	if ok := authenticate(conn); ok != true {
		return
	}

	// proc request
	procRequest(conn)
}

func authenticate(conn net.Conn) bool {
	// request from client
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+

	fmt.Println("Start authenticate ...")

	nmethods := make([]uint8, 1)
	_, err := io.ReadAtLeast(conn, nmethods, 1)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	mNum := int(nmethods[0])
	methods := make([]uint8, mNum)
	_, err = io.ReadAtLeast(conn, methods, mNum)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	// response to client
	// +----+--------+
	// |VER | STATUS |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+

	// currently, only support None and UsrPwd
	for _, m := range methods {
		switch m {
		case authNone:
			fmt.Println("Use authNone ...")
			_, err = conn.Write([]uint8{socks5Version, authNone})
			if err != nil {
				return false
			} else {
				return true
			}
		case authUsrPwd:
			fmt.Println("Check usr/pwd ...")
			return subNegotiation(conn)
		}
	}

	// no acceptable auth method
	fmt.Println("No acceptable auth method found ...")
	conn.Write([]uint8{socks5Version, noAcceptableAuth})
	return false
}

func subNegotiation(conn net.Conn) bool {
	_, err := conn.Write([]uint8{socks5Version, authUsrPwd})
	if err != nil {
		fmt.Printf("subNegotiation write: %s\n", err.Error())
		return false
	}

	// RFC 1929
	// subnegotiation version
	ver := make([]uint8, 1)
	_, err = io.ReadAtLeast(conn, ver, 1)
	if err != nil {
		fmt.Printf("subNegotiation read: %s\n", err.Error())
		return false
	}

	if ver[0] != negotiationVer {
		fmt.Printf("invalid negotiation version: %0x,should be %0x\n", ver[0], negotiationVer)
		return false
	}

	// usr
	usrLen := make([]uint8, 1)
	_, err = io.ReadAtLeast(conn, usrLen, 1)
	if err != nil {
		fmt.Printf("subNegotiation usr: %s\n", err.Error())
		return false
	}

	uNum := int(usrLen[0])
	usr := make([]uint8, uNum)
	_, err = io.ReadAtLeast(conn, usr, uNum)

	// pwd
	pwdLen := make([]uint8, 1)
	_, err = io.ReadAtLeast(conn, pwdLen, 1)
	if err != nil {
		fmt.Printf("subNegotiation pwd: %s\n", err.Error())
		return false
	}

	pNum := int(pwdLen[0])
	pwd := make([]uint8, pNum)
	_, err = io.ReadAtLeast(conn, pwd, pNum)

	// validate usr pwd
	ok := validateUsrPwd(string(usr), string(pwd))
	if !ok {
		_, err = conn.Write([]byte{negotiationVer, authFail})
	} else {
		_, err = conn.Write([]byte{negotiationVer, authOK})
	}

	if err != nil {
		fmt.Printf("subNegotiation validate: %s\n", err.Error())
		return false
	}
	fmt.Println("auth usr pwd ok:", string(usr), string(pwd))
	return true
}

func validateUsrPwd(usr, pwd string) bool {
	var validUsrPwd map[string]string = map[string]string{
		"kumakichi": "kumakichi",
		"sans":      "sans",
		// add more usr-pwd pair here ...
	}
	if validUsrPwd[usr] == "" {
		fmt.Printf("Invalid usr/pwd : <%s-%s>\n", usr, pwd)
		return false
	}
	return true
}

func procRequest(conn net.Conn) {
	// request from client
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	// ver
	buff := make([]uint8, 3)
	_, err := io.ReadAtLeast(conn, buff, 3)
	if err != nil {
		fmt.Println("procRequest ver:", err.Error())
		return
	}
	if buff[0] != socks5Version {
		fmt.Printf("Unsupported socks version : %0x\n", buff[0])
		return
	}

	// cmd, currently, only support CONNECT, BIND or UDP ASSOCIATE is not supported
	cmd := buff[1]

	// atyp
	var dstAddr net.IP
	abuff := make([]byte, 1)
	_, err = io.ReadAtLeast(conn, abuff, 1)
	if err != nil {
		fmt.Println("procRequest atyp:", err.Error())
		return
	}
	atyp := abuff[0]
	// response to client
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	fmt.Printf("atyp: %0x\n", atyp)
	switch atyp {
	case atypIPV4:
		addrv4 := make([]byte, 4)
		_, err = io.ReadAtLeast(conn, addrv4, 4)
		if err != nil {
			fmt.Println("atypIPV4:", err.Error())
			return
		}
		dstAddr = net.IP(addrv4)
	case atypDomain:
		length := make([]byte, 1)
		_, err = io.ReadAtLeast(conn, length, 1)
		if err != nil {
			fmt.Println("atypDomain:", err.Error())
			return
		}
		addrLen := int(length[0])
		addrDomain := make([]byte, addrLen)
		_, err = io.ReadAtLeast(conn, addrDomain, addrLen)
		if err != nil {
			fmt.Println("atypDomain:", err.Error())
			return
		}
		fmt.Printf("Domain: %s\n", string(addrDomain))
		// resolve
		ipAddr, err := net.ResolveIPAddr("ip", string(addrDomain))
		if err != nil {
			fmt.Println("atypDomain:", err.Error())
			return
		}
		dstAddr = ipAddr.IP
	case atypIPV6:
		addrv6 := make([]byte, 16)
		_, err = io.ReadAtLeast(conn, addrv6, 16)
		if err != nil {
			fmt.Println("atypIPV6:", err.Error())
			return
		}
		dstAddr = net.IP(addrv6)
	default:
		fmt.Printf("Unsupported atyp : %0x\n", buff[0])
		return
	}

	// port
	port := make([]byte, 2)
	_, err = io.ReadAtLeast(conn, port, 2)
	dstPort := int(port[0])<<8 + int(port[1]) // big endian
	fmt.Printf("dstAddr:%v,dstPort: %d,%v\n", dstAddr, dstPort, port)

	switch cmd {
	case cmdConnect:
		procConnect(conn, atyp, dstAddr, dstPort)
	default:
		fmt.Printf("Unsupported command : %0x\n", buff[1])
		return
	}
}

func procConnect(conn net.Conn, atyp uint8, dstAddr net.IP, dstPort int) {
	fmt.Println("start connect ...")
	// do connect job
	addr := net.TCPAddr{IP: dstAddr, Port: dstPort}
	rmtConn, err := net.DialTCP("tcp", nil, &addr)
	if err != nil {
		// TODO: specify detailed err type
		fmt.Println("procConnect:", err.Error())
		return
	}
	defer rmtConn.Close()
	fmt.Println("connect ok.")

	// connect ok
	local := rmtConn.LocalAddr().(*net.TCPAddr)
	fmt.Printf("bind addr is : %v\n", local)
	if err := sendCmdReply(conn, cmdRepSucceeded, local.IP, local.Port); err != nil {
		fmt.Println("error send reply: ", err.Error())
		return
	} else {
		fmt.Println("Send succeed reply ok.")
	}

	forwardRequest(rmtConn, conn)
	fmt.Println("done.")
}

func forwardRequest(rmt, local net.Conn) {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go forward(rmt, local, wg) // proc client request
	go forward(local, rmt, wg) // send result to client
	wg.Wait()
}

func forward(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	n, err := io.Copy(dst, src)
	if err != nil {
		fmt.Printf("error forward : %s\n", err.Error())
	}
	fmt.Printf("Copied %d bytes from %s to %s.\n", n, src.LocalAddr().String(), dst.LocalAddr().String())
}

func sendCmdReply(conn net.Conn, rep uint8, ip net.IP, port int) error {
	var addr []byte

	p1 := byte((port & 0xff00) >> 8)
	p2 := byte(port & 0xff)
	atyp := byte(0x00)
	msg := []byte{socks5Version, rep, 0x00}

	if ip.To4() != nil { // v4
		addr = []byte(ip.To4())
		atyp = atypIPV4
	} else { // v6
		addr = []byte(ip.To16())
		atyp = atypIPV4
	}
	msg = append(msg, atyp)
	msg = append(msg, addr...)
	msg = append(msg, p1, p2)
	_, err := conn.Write(msg)
	return err
}
