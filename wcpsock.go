package wcp

import (
	"net"
)


func ListenWCP(network string, laddr *net.UDPAddr) (*WCPListener, error ) {
	Assert(network == "wcp")
	return _wcp.impl_ListenWCP( laddr)
}

func DialWCP(network string, laddr, raddr *net.UDPAddr) (*WCPConn, error) {
	Assert(network == "wcp")
	return _wcp.impl_DialWCP( raddr )
}

func (l *WCPListener) AcceptWCP() (*WCPConn, error ) {
	return l.impl_AcceptWCP()
}

func (l *WCPListener) Close() error {
	return l.impl_Close()
}

func (c *WCPConn) Read(b []byte) (int, error) {
	return c.WCB.read(b)
}

func (c *WCPConn) Write(b []byte) (int, error){
	return c.WCB.write(b)
}

func (c *WCPConn) Close() error {
	return c.WCB.close()
}

/*
func (l *WCPListener) Close() error {

}

func (l *WCPListener) Addr() net.Addr {

}




func (c *WCPConn) CloseRead() error {

}

func (c *WCPConn) CloseWrite() error {

}
*/





