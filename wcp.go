package wcp

import (
	"net"
	"sync"
	"container/list"
	"sync/atomic"
	"syscall"
	"errors"
	"io"
	"time"
	"bytes"
	"log"
)

//define
const (
	WCP_MTU  		= 1400
	WCP_HeaderLen 	= 16
	WCP_MDU 		= (WCP_MTU-WCP_HeaderLen)
	WCP_RCV_BUFFER_MAX = (1024*1024)
	WCP_RCV_BUFFER_MIN = (WCP_MDU*4)
	WCP_RCV_WND_DEFAULT = (64*1024)

	WCP_SND_BUFFER_MAX = (1024*1024)
	WCP_SND_BUFFER_MIN = (1024*1024)
	WCP_SND_WND_DEFAULT = (64*1024)

	WCP_SND_SSTHRESH_MAX = (1024*1024*2)
	WCP_SND_SSTHRESH_MIN = (4*WCP_MTU)
	WCP_SND_SSTHRESH_DEFAULT = WCP_SND_SSTHRESH_MAX

	WCP_SND_CWND_MAX =(WCP_SND_SSTHRESH_MAX*4)
	WCP_SND_SACK_DUP_COUNT = 1

	WCP_RWND_CHECK_GRANULARITY = 1000
	WCP_SRTT_ALPHA = 1/8
	WCP_RTTVAR_BETA = 1/4

	WCP_RTO_CLOCK_GRANULARITY=5
	WCP_RTO_INIT = 1000
	WCP_RTO_MIN = 200
	WCP_RTO_MAX = (60*1000)

	WCP_LOST_THRESHOLD=3
	WCP_FAST_RECOVERY_THRESHOLD=2
	WCP_FAST_RETRANSMIT_GRAULARITY=5

	WCP_SYN_MAX_TIME = (30*1000*10)
	WCP_FIN_MAX_TIME = (2*60*1000)
	WCP_TIMEWAIT_MAX_TIME = (2*60*1000)
	WCP_LAST_ACK_MAX_TIME = (30*1000)

	WCP_BACKLOG_DEFAULT = 128
)

//wcp packet flag
const (
	WCP_FLAG_SYN  int16	= 1<<0
	WCP_FLAG_ACK  	= 1<<1
	WCP_FLAG_SACK 	= 1<<2
	WCP_FLAG_FIN 	= 1<<3
	WCP_FLAG_RST 	= 1<<4
	WCP_FLAG_WND 	= 1<<5
	WCP_FLAG_DAT	= 1<<6
	WCP_FLAG_KEEP_ALIVE = 1<<7
	WCP_FLAG_KEEP_ALIVE_REPLY = 1<<8
)

func four_tuple_hash( addr1 *net.UDPAddr, addr2 *net.UDPAddr ) int {
	var addr1ulongip = ReadU32(addr1.IP)
	var addr2ulongip = ReadU32(addr2.IP)
	return int((addr1ulongip*59) ^ (addr2ulongip) ^ uint32(addr1.Port<<16) ^ uint32(addr2.Port))
}

func UDPADDR_EQUAL( left *net.UDPAddr, right *net.UDPAddr ) bool {
	return (left.Port == right.Port) && (bytes.Compare(left.IP, right.IP) == 0)
}

func WCPPACK_TEST_FLAG( flag int16, _flag int16) bool {	return (flag&_flag) != 0 }

func WCPPACK_TO_UDPMESSAGE( pack *wcbPack ) []byte {
	b := make([]byte, WCP_MTU)

	var wlen uint32
	WriteU32(b[wlen:], pack.header.seq)
	wlen += 4

	WriteU32(b[wlen:], pack.header.ack)
	wlen += 4

	WriteU32(b[wlen:], pack.header.wnd)
	wlen += 4

	WriteI16(b[wlen:], pack.header.flag)
	wlen += 2

	if pack.data != nil && pack.data.Len > 0 {
		WriteU16(b[wlen:], pack.data.Len)
		wlen +=2

		WriteBytes(b[wlen:], pack.data.Buf[:pack.data.Len])
		wlen += uint32(pack.data.Len)
	} else {
		WriteU16(b[wlen:],0)
		wlen += 2
	}

	return b[:wlen]
}

func WCPPACK_FROM_UDPMESSAGE( b []byte, nbytes uint16 ) (pack *wcbReceivedPack, err error) {

	var rlen uint16
	if (rlen + 4) > nbytes {
		return nil, errors.New("invalid incoming pack [read seq]")
	}

	var _pack = &wcbReceivedPack{
		header:NewWCPHeader(),
		data:NewPack(),
		from:nil,
	}

	_pack.header.seq = ReadU32(b[rlen:])
	rlen += 4

	if (rlen+4) > nbytes {
		return nil, errors.New("invalid incoming pack [read ack]")
	}
	_pack.header.ack = ReadU32(b[rlen:])
	rlen += 4

	if (rlen +4) > nbytes {
		return nil, errors.New("invalid incoming pack [read wnd]")
	}
	_pack.header.wnd = ReadU32(b[rlen:])
	rlen += 4

	if (rlen+2) > nbytes {
		return nil, errors.New("invalid incoming pack [read flag]")
	}
	_pack.header.flag = ReadI16(b[rlen:])
	rlen += 2

	if (rlen+2) > nbytes {
		return nil, errors.New("invalid incoming pack [read dlen]")
	}
	_pack.header.dlen = ReadU16(b[rlen:])
	rlen += 2

	if _pack.header.dlen > 0 {
		if _pack.header.dlen > (nbytes - rlen) {
			return nil, errors.New("invalid incoming pack [read data]")
		}

		Assert( _pack.header.dlen <= WCP_MDU )
		_pack.data.Len = uint16(ReadBytes(_pack.data.Buf, b[rlen:rlen+_pack.header.dlen]))
		Assert( _pack.data.Len == _pack.header.dlen )
	}

	return _pack, nil
}

func INJECT_TO_ADDRESS(udpcon net.PacketConn, pack *wcbPack, raddr *net.UDPAddr) (err error) {
	s := WCPPACK_TO_UDPMESSAGE(pack)
	_, err = udpcon.WriteTo(s, raddr )
	return
}

func REPLY_RST_TO_ADDRESS(udpconn net.PacketConn, seq uint32, raddr *net.UDPAddr ) error {

	var pack = &wcbPack{
		header: &wcpHeader{
			seq:seq,
			flag:WCP_FLAG_RST,
		},
	}

	return INJECT_TO_ADDRESS(udpconn, pack, raddr)
}

//wcp cwnd cfg
const (
	WCP_IW = 10
	WCP_LW = 5
	WCP_RW = 5
)

//WCB state
const (
	WCB_CLOSED = iota
	WCB_LISTEN
	WCB_SYNING
	WCB_SYN_SENT
	WCB_SYN_RECEIVED
	WCB_FIN_WAIT_1
	WCB_CLOSING
	WCB_FIN_WAIT_2
	WCB_ESTABLISHED
	WCB_CLOSE_WAIT
	WCB_TIME_WAIT
	WCB_LAST_ACK
	WCB_RECYCLE
)

//WCB flag
const (
	RCV_ARRIVE_NEW int16 = 1<<0

	SND_BIGGEST_SACK_UPDATE = 1<<1
	SND_UNA_UPDATE = 1<<2
	SND_FAST_RECOVERED = 1<<3
	SND_CWND_SLOW_START = 1<<4
	SND_CWND_CONGEST_AVOIDANCE = 1<<5
	SND_LOST_DETECTED = 1<<6

	WCB_FLAG_IS_LISTENER = 1<<7
	WCB_FLAG_IS_PASSIVE_OPEN = 1<<8
	WCB_FLAG_IS_ACTIVE_OPEN = 1<<9
	WCB_FLAG_FIRST_RTT_DONE = 1<<10
	WCB_FLAG_CLOSED_CALLED = 1<<11
)

type pack struct {
	Buf []byte
	Len uint16
}

func NewPack() *pack {
	return &pack{
		Buf: make([]byte, WCP_MTU),
		Len:0,
	}
}

type wcpHeader struct {
	seq uint32
	ack uint32
	wnd uint32
	flag int16
	dlen uint16
}

func NewWCPHeader() *wcpHeader {
	return &wcpHeader{}
}

type wcbReceivedPack struct {
	header *wcpHeader
	data *pack
	from *net.UDPAddr
}

func NewWcbReceivedPack() *wcbReceivedPack {
	return &wcbReceivedPack{
		header: NewWCPHeader(),
		data: NewPack(),
	}
}

type wcbPack struct {
	header *wcpHeader
	data *pack
	sent_ts uint64
	sent_times uint32
}

func NewWcbPack() *wcbPack {
	return &wcbPack{
		header:NewWCPHeader(),
		data:NewPack(),
	}
}

type wcbSndInfo struct {
	dsn uint32
	next uint32
	una uint32
	ssthresh uint32
	cwnd uint32
	rwnd uint32
}

type wcbRcvInfo struct {
	wnd uint32
	next uint32
}

//read flag
const (
	READ_RWND_LESS_THAN_MTU 	= 1
	READ_RWND_MORE_THAN_MTU 	= 1<<1
	READ_REMOTE_FIN_RECEIVED 	= 1<<2
	READ_REMOTE_FIN_READ_BY_USER = 1<<3
	READ_LOCAL_READ_SHUTDOWNED = 1<<4
	READ_RECV_ERROR = 1<<5
)

//write flag
const (
	WRITE_LOCAL_FIN_SENT = 1
	WRITE_LOCAL_WRITE_SHUTDOWNED = 1<<1
	WRITE_SEND_ERROR = 1<<2
)

const (
	WCB_SHUTDOWN_RD int = 0x01
	WCB_SHUTDOWN_WR int = 0x10
	WCB_SHUTDOWN_RDWR int = 0x11
)

type wcbKeepaliveVals struct {
	idle uint16
	interval uint16
	probes uint16
}

type wcb struct {
	udpconn net.PacketConn
	fd int

	four_tuple_hash_id int

	mutex sync.Mutex
	cond *Condition

	state uint8
	timer_state uint64

	wcb_errno error
	wcb_option int

	wcb_flag int16

	//r for recv, s for send
	r_flag int8
	s_flag int8

	laddr *net.UDPAddr
	raddr *net.UDPAddr

	rto uint32
	srtt uint32
	rttvar uint32

	received_vec_mutex sync.Mutex
	received_vec []*wcbReceivedPack
	received_vec_standby []*wcbReceivedPack

	rcv_info wcbRcvInfo
	rcv_received list.List

	r_mutex sync.Mutex
	r_cond *Condition

	rb *BytesRingbuffer
	rb_standby *BytesRingbuffer

	r_timer_last_rwnd_update uint64

	backloglist_pending list.List
	backlogq list.List
	backlog_size int

	snd_biggest_ack uint32
	snd_lost_detected_timer uint64
	snd_lost_biggest_seq uint32
	snd_lost_cwnd_for_fast_recover_compensation uint32
	snd_lost_bigger_than_lost_seq_time uint8

	snd_timer_cwnd_congest_avoidance uint64
	snd_info wcbSndInfo
	snd_sending list.List

	snd_nflight_bytes uint32
	snd_nflight_bytes_max uint32
	snd_flights list.List

	snd_last_rto_timer uint64
	snd_sacked_pack_tmp *Packet


	s_mutex sync.Mutex
	s_cond *Condition
	sb *BytesRingbuffer
	s_sending_standby list.List
	s_sending_ignore_seq_space list.List

	keepalive_timer_last_received_pack uint64
	keepalive_vals wcbKeepaliveVals
	keepalive_probes_sent uint16
}

func NewWCB() *wcb {
	return new(wcb)
}

func (b *wcb) init() {
	b.mutex.Lock()
	b.cond = NewCondition()

	b.timer_state = 0
	b.state = WCB_CLOSED
	b.wcb_flag = 0
	b.wcb_option = 0
	b.wcb_errno = nil

	b.rto = WCP_RTO_INIT

	b.received_vec = make([]*wcbReceivedPack,0,256)
	b.received_vec_standby = make([]*wcbReceivedPack,0, 256)

	b.rcv_info.next = 0
	b.rcv_info.wnd = WCP_RCV_WND_DEFAULT


	b.wcb_flag = 0
	b.r_flag = 0
	b.r_cond = NewCondition()

	b.s_flag = 0
	b.s_cond = NewCondition()
	b.r_timer_last_rwnd_update = 0

	b.snd_biggest_ack = 0
	b.wcb_flag = SND_CWND_SLOW_START
	b.snd_lost_detected_timer = 0
	b.snd_lost_biggest_seq = 0


	b.snd_info.dsn = 0
	b.snd_info.next = 0
	b.snd_info.una = 0
	b.snd_info.ssthresh = WCP_SND_SSTHRESH_DEFAULT
	b.snd_info.cwnd = WCP_IW*WCP_MTU
	b.snd_info.rwnd = WCP_RCV_WND_DEFAULT

	b.snd_timer_cwnd_congest_avoidance =0
	b.snd_nflight_bytes = 0
	b.snd_nflight_bytes_max = 0
	b.snd_last_rto_timer = 0

	b.snd_sacked_pack_tmp = NewPacket(64*1024)

	b.rb = NewBytesRingBuffer(WCP_RCV_WND_DEFAULT)
	b.rb_standby = NewBytesRingBuffer(WCP_RCV_WND_DEFAULT)

	b.sb = NewBytesRingBuffer(WCP_SND_WND_DEFAULT)

	b.backlog_size = 128
	b.keepalive_timer_last_received_pack = UnixMill()
	b.keepalive_vals.idle = 60
	b.keepalive_vals.interval = 60
	b.keepalive_vals.probes = 5
	b.keepalive_probes_sent = 0

	b.mutex.Unlock()
}

func (b *wcb) deinit() {
	b.cond.Close()
	b.r_cond.Close()
	b.s_cond.Close()
}

func (b *wcb) get_rcv_buffer_size() int {
	return int(b.rb.Capacity()>>1)
}

func (b *wcb) set_rcv_buffer_size(size int) error {
	b.mutex.Lock()

	if b.state == WCB_CLOSED {
		b.mutex.Unlock()
		return syscall.EBADFD
	}

	var _size = MinUint32( uint32(size), WCP_RCV_BUFFER_MAX)
	_size = MaxUint32(_size, WCP_RCV_BUFFER_MIN)

	b.rb = NewBytesRingBuffer(_size<<1)
	b.rb_standby = NewBytesRingBuffer(_size<<1)

	b.rcv_info.wnd = b.rb.Capacity()
	b.mutex.Unlock()

	return nil
}

func (b *wcb) get_snd_buffer_size() int {
	return int(b.sb.Capacity()>>1)
}

func (b *wcb) set_snd_buffer_size( size int ) error {
	b.mutex.Lock()
	if b.state != WCB_CLOSED {
		b.mutex.Unlock()
		return syscall.EBADFD
	}

	var _size = MinUint32( uint32(size), WCP_SND_BUFFER_MAX)
	_size = MaxUint32(_size, WCP_SND_BUFFER_MIN)

	b.sb = NewBytesRingBuffer( _size<<1 )
	b.mutex.Unlock()

	return nil
}


func (b *wcb) SYN() {
	Assert( b.state == WCB_CLOSED )

	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_SYN ,
		},
	}
	b.snd_info.dsn++
	b.s_sending_standby.PushBack(opack)
}

func (b *wcb) SYNACK() {
	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_ACK ,
		},
	}
	b.snd_info.dsn++
	b.s_sending_standby.PushBack(opack)
}

func (b *wcb) SYNSYNACK() {
	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_SYN|WCP_FLAG_ACK ,
		},
	}
	b.snd_info.dsn++
	b.s_sending_standby.PushBack(opack)
}

func (b *wcb) FIN() {
	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_FIN ,
		},
	}
	b.snd_info.dsn++
	b.s_sending_standby.PushBack(opack)
}

func (b *wcb) FINACK() {
	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_ACK ,
		},
	}
	b.snd_info.dsn++
	b.s_sending_standby.PushBack(opack)
}


func (b *wcb) SACK( sacked_packet *Packet) {
	var pack_acked_max_bytes = (WCP_MDU/4)*4

	for sacked_packet.Len() > 0 {
		var wcbPack= NewWcbPack()

		wcbPack.header.seq = b.snd_info.dsn
		wcbPack.header.flag = WCP_FLAG_SACK

		wcbPack.data.Len = uint16(sacked_packet.Read(wcbPack.data.Buf, uint32(pack_acked_max_bytes)))
		wcbPack.header.dlen = wcbPack.data.Len

		b.s_sending_ignore_seq_space.PushBack(wcbPack)

		for i := 0 ; i< WCP_SND_SACK_DUP_COUNT ;i++ {
			b.s_sending_ignore_seq_space.PushBack(wcbPack)
		}
	}
}

func (b *wcb) keepalive() {
	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_KEEP_ALIVE ,
		},
	}
	b.s_sending_ignore_seq_space.PushBack(opack)
}

func (b *wcb) keepalive_reply() {
	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_KEEP_ALIVE_REPLY ,
		},
	}
	b.s_sending_ignore_seq_space.PushBack(opack)
}

func (b *wcb) update_rwnd() {
	var opack = &wcbPack{
		header: &wcpHeader {
			seq:b.snd_info.dsn,
			flag: WCP_FLAG_WND ,
		},
	}
	b.s_sending_ignore_seq_space.PushBack(opack)
}


func (b *wcb) SYN_RCVD( incoming *wcbReceivedPack) {
	b.mutex.Lock()
	Assert( b.state == WCB_CLOSED)
	b.PACK_RCVD(incoming)
	b.state = WCB_SYN_RECEIVED
	b.mutex.Unlock()
}

func (b *wcb) PACK_RCVD( incoming *wcbReceivedPack) {
	b.received_vec_mutex.Lock()
	b.received_vec_standby = append(b.received_vec_standby, incoming )
	b.received_vec_mutex.Unlock()
}

func (b *wcb) check_cwnd( check_size uint32 ) {

	if (b.wcb_flag&SND_CWND_SLOW_START) != 0 {
		b.snd_info.cwnd += check_size

		if b.snd_info.cwnd >= b.snd_info.ssthresh {
			b.wcb_flag &= (^SND_CWND_SLOW_START)
			b.wcb_flag |= SND_CWND_CONGEST_AVOIDANCE
		}
	} else if (b.wcb_flag&SND_CWND_CONGEST_AVOIDANCE) != 0 {

		now := UnixMill()

		if uint32(now-b.snd_timer_cwnd_congest_avoidance) >= b.srtt {
			b.snd_info.cwnd += WCP_MTU
			b.snd_timer_cwnd_congest_avoidance = now
		}
	} else {}

	if b.snd_info.cwnd > WCP_SND_CWND_MAX {
		b.snd_info.cwnd = WCP_SND_CWND_MAX
	}
}

func (b *wcb) handle_pack_acked( pack *wcbPack, now uint64 ) {

	if pack.sent_times == 1 {
		var	rtt = uint32(now - pack.sent_ts)

		if b.wcb_flag&WCB_FLAG_FIRST_RTT_DONE != 0 {
			b.wcb_flag |= WCB_FLAG_FIRST_RTT_DONE
			b.srtt = rtt
			b.rttvar = rtt>>1

			if 2*b.rttvar < WCP_RTO_CLOCK_GRANULARITY {
				b.rto  = b.srtt + WCP_RTO_CLOCK_GRANULARITY
			} else {
				b.rto = b.srtt + 2*b.rttvar
			}
		} else {
			b.rttvar = (1-WCP_RTTVAR_BETA)*b.rttvar + WCP_RTTVAR_BETA*uint32(AbsUint32( b.srtt,rtt ))
			b.srtt = (1-WCP_SRTT_ALPHA)*b.srtt + WCP_SRTT_ALPHA*rtt

			if 2*b.rttvar < WCP_RTO_CLOCK_GRANULARITY {
				b.rto = b.srtt + WCP_RTO_CLOCK_GRANULARITY
			} else {
				b.rto = b.srtt + 2*b.rttvar
			}
		}

		if b.rto > WCP_RTO_MAX {
			b.rto = WCP_RTO_MAX
		} else if b.rto < WCP_RTO_MIN {
			b.rto = WCP_RTO_MIN
		} else {}
	}


	var ntotalBytes = uint32(pack.header.dlen) + WCP_HeaderLen
	Assert( b.snd_nflight_bytes >= ntotalBytes )
	b.snd_nflight_bytes -= ntotalBytes
	b.check_cwnd(ntotalBytes)
}

func (b *wcb) Update(now uint64) uint8 {

	switch b.state {
	case WCB_CLOSED:
		{
			if (b.r_flag&READ_LOCAL_READ_SHUTDOWNED != 0) && (b.s_flag&WRITE_LOCAL_WRITE_SHUTDOWNED != 0) {
				b.mutex.Lock()
				if b.wcb_flag&WCB_FLAG_CLOSED_CALLED != 0 {
					b.state = WCB_RECYCLE
				}
				b.mutex.Unlock()
			}
		}
	case WCB_LISTEN:
		{
			if ( b.r_flag&READ_LOCAL_READ_SHUTDOWNED ) == 0 {
				b.listen_handle_incoming()
			}

			b.r_mutex.Lock()
			for item := b.backloglist_pending.Front(); item != nil ; item = item.Next()  {
				s := item.Value.(*wcb).Update(now)
				if s == WCB_ESTABLISHED {
					b.backlogq.PushBack(item.Value.(*wcb))
					b.backloglist_pending.Remove(item)
					b.r_cond.Notify()
				} else if s == WCB_CLOSE_WAIT || s == WCB_CLOSED {
					item.Value.(*wcb).close()
					b.backloglist_pending.Remove(item)
				} else if s == WCB_SYN_RECEIVED {
					//
				} else {
					b.r_mutex.Unlock()
					panic("wcp logic issue")
				}
			}
			b.r_mutex.Unlock()
		}
	case WCB_SYNING:
		{
			b.check_flights(now)
			b.check_send(now)
		}
	case WCB_SYN_SENT:
		{
			if now - b.timer_state >= WCP_SYN_MAX_TIME {
				b.mutex.Lock()
				b.state = WCB_CLOSED
				b.wcb_errno = syscall.ETIMEDOUT
				b.cond.Notify()
				b.mutex.Unlock()
			} else {
				b.check_recv(now)
				b.check_flights(now)
				b.check_send(now)
			}
		}
	case WCB_SYN_RECEIVED, WCB_ESTABLISHED, WCB_CLOSE_WAIT:
		{
			if b.wcb_errno != nil {
				b.mutex.Lock()
				b.state = WCB_CLOSED
				b.mutex.Unlock()
			} else {
				b.check_recv(now)
				b.check_flights(now)
				b.check_send(now)
			}
		}
	case WCB_FIN_WAIT_1, WCB_CLOSING, WCB_FIN_WAIT_2:
		{
			if b.wcb_errno != nil || (now - b.timer_state) >= WCP_FIN_MAX_TIME {
				b.mutex.Lock()
				b.state = WCB_CLOSED
				b.mutex.Unlock()
			} else {
				b.check_recv(now)
				b.check_flights(now)
				b.check_send(now)
			}
		}
	case WCB_LAST_ACK:
		{
			if b.wcb_errno != nil || (now - b.timer_state) >= WCP_LAST_ACK_MAX_TIME {
				b.mutex.Lock()
				b.state = WCB_CLOSED
				b.mutex.Unlock()
			} else {
				b.check_recv(now)
				b.check_flights(now)
				b.check_send(now)
			}
		}
	case WCB_TIME_WAIT:
		{
			if (now - b.timer_state) >= WCP_TIMEWAIT_MAX_TIME {
				b.mutex.Lock()
				b.state = WCB_CLOSED
				b.mutex.Unlock()
			}
		}
	case WCB_RECYCLE:
		{}
	}

	return b.state
}

func (b *wcb) check_recv( now uint64) {

	{
		if len(b.received_vec) != 0 {
			b.received_vec = b.received_vec[0:0]
		}

		b.received_vec_mutex.Lock()
		if len(b.received_vec_standby) != 0 {
			b.received_vec, b.received_vec_standby = b.received_vec_standby, b.received_vec
		}
		b.received_vec_mutex.Unlock()
	}

	var received_size = len(b.received_vec)

	if received_size == 0 {
		timediff := ((now - b.keepalive_timer_last_received_pack)/1000)

		if b.keepalive_probes_sent >= b.keepalive_vals.probes {
			b.r_mutex.Lock()
			b.r_flag |= READ_RECV_ERROR
			b.wcb_errno = syscall.ETIMEDOUT
			b.r_mutex.Unlock()
		} else if ( timediff >= uint64(b.keepalive_vals.idle + (b.keepalive_vals.interval*b.keepalive_probes_sent))) {
			b.keepalive()
			b.keepalive_probes_sent++
		} else {}
	} else {
		b.keepalive_timer_last_received_pack = now
		b.keepalive_probes_sent = 0

		acked_queue := make([]uint32, 0,1024 )

		for i := 0; i < received_size; i++ {

			if b.snd_info.una < b.received_vec[i].header.ack {
				b.snd_info.una = b.received_vec[i].header.ack
				b.wcb_flag |= SND_UNA_UPDATE
				b.snd_info.rwnd = b.received_vec[i].header.wnd

				log.Printf("UNA_UPDADTE TO: %d\n", b.snd_info.una )
			}

			if WCPPACK_TEST_FLAG(b.received_vec[i].header.flag, WCP_FLAG_WND) {
				b.snd_info.rwnd = b.received_vec[i].header.wnd
			}

			if WCPPACK_TEST_FLAG(b.received_vec[i].header.flag, WCP_FLAG_SACK) {
				Assert(b.received_vec[i].data != nil && b.received_vec[i].data.Len != 0)
				var idx uint16
				for idx < b.received_vec[i].data.Len {
					acked_queue = append(acked_queue, ReadU32( b.received_vec[i].data.Buf[idx:] ))
					idx += 4
				}

				continue
			}

			if WCPPACK_TEST_FLAG(b.received_vec[i].header.flag, WCP_FLAG_KEEP_ALIVE) {
				b.keepalive_reply()
				continue
			}

			if WCPPACK_TEST_FLAG(b.received_vec[i].header.flag, WCP_FLAG_KEEP_ALIVE_REPLY) {
				continue
			}

			b.snd_sacked_pack_tmp.WriteU32(b.received_vec[i].header.seq)

			if b.received_vec[i].header.seq < b.rcv_info.next {
				continue;
			}

			var e = b.rcv_received.Back()

			if e == nil {
				b.rcv_received.PushBack(b.received_vec[i])
			} else {
				for {
					var tmp= e.Value.(*wcbReceivedPack)

					if tmp.header.seq == b.received_vec[i].header.seq {
						goto _end_insert_loop
					} else if b.received_vec[i].header.seq < tmp.header.seq {
						e = e.Prev()
						Assert( e != nil )
						Assert( e != b.rcv_received.Back())
						continue
					} else {
						break
					}
				}
				b.rcv_received.InsertAfter(b.received_vec[i], e)
			_end_insert_loop:
			}
		}

		if b.snd_sacked_pack_tmp.Len() != 0 {
			b.SACK(b.snd_sacked_pack_tmp)
			b.snd_sacked_pack_tmp.Reset()
		}

		for i, qsize := 0, len(acked_queue); i < qsize; i++ {
			ack := acked_queue[i]
			if ack < b.snd_info.una {
				continue
			}

			if ack > b.snd_biggest_ack {
				b.snd_biggest_ack = ack
				b.wcb_flag |= SND_BIGGEST_SACK_UPDATE
			}


			var ee *list.Element
			for e := b.snd_flights.Front(); e != nil;  {
				if e.Value.(*wcbPack).header.seq == ack {
					b.handle_pack_acked(e.Value.(*wcbPack), now)
					ee = e
					e = e.Next()
					b.snd_flights.Remove(ee)
					break
				} else {
					e = e.Next()
				}
			}

			if (b.wcb_flag&SND_LOST_DETECTED) != 0 && ack > b.snd_lost_biggest_seq {
				b.snd_lost_bigger_than_lost_seq_time++

				if b.snd_lost_bigger_than_lost_seq_time >= 1 && b.snd_info.una > b.snd_lost_biggest_seq {
					b.snd_info.cwnd += b.snd_lost_cwnd_for_fast_recover_compensation
					if b.snd_info.cwnd > WCP_SND_CWND_MAX {
						b.snd_info.cwnd = WCP_SND_CWND_MAX
					}

					new_ssthresh := b.snd_info.cwnd
					if new_ssthresh > WCP_SND_SSTHRESH_MAX {
						new_ssthresh = WCP_SND_SSTHRESH_MAX
					}

					if b.snd_info.ssthresh < new_ssthresh {
						b.snd_info.ssthresh = new_ssthresh
					}

					b.snd_lost_cwnd_for_fast_recover_compensation = 0
					b.wcb_flag |= SND_FAST_RECOVERED
					b.wcb_flag &= ^SND_LOST_DETECTED
				}
			}
		} //END OF ACKQUEUE

		var ee *list.Element
		for e := b.rcv_received.Front(); e != nil; {
			ee = e
			e = e.Next()

			var incoming = ee.Value.(*wcbReceivedPack)
			if incoming.header.seq != b.rcv_info.next {
				break;
			}

			if incoming.header.dlen > 0 {
				if !UDPADDR_EQUAL(incoming.from, b.raddr) {
					REPLY_RST_TO_ADDRESS(b.udpconn, incoming.header.ack, incoming.from)

					b.mutex.Lock()
					b.state = WCB_CLOSED
					b.wcb_errno = syscall.ECONNABORTED
					b.mutex.Unlock()
					break
				}

				if b.rb_standby.LeftCapacity() < uint32(incoming.header.dlen) {
					b.r_flag |= READ_RWND_LESS_THAN_MTU
					break
				}

				b.rb_standby.Write(incoming.data.Buf, uint32(incoming.data.Len))
				b.rcv_info.wnd = b.rb_standby.LeftCapacity()

				if b.rcv_info.wnd <= WCP_MTU {
					b.r_flag |= READ_RWND_LESS_THAN_MTU
				} else {
					b.r_flag &= ^(READ_RWND_LESS_THAN_MTU | READ_RWND_MORE_THAN_MTU)
				}
			}
			b.rcv_info.next++

			if WCPPACK_TEST_FLAG(incoming.header.flag, WCP_FLAG_RST) {
				b.mutex.Lock()
				b.wcb_errno = syscall.ECONNRESET
				b.state = WCB_CLOSED
				b.cond.Notify()
				b.mutex.Unlock()

				b.r_mutex.Lock()
				b.r_cond.Notify()
				b.r_mutex.Unlock()
				break
			}

			if WCPPACK_TEST_FLAG(incoming.header.flag, WCP_FLAG_SYN) {
				b.mutex.Lock()
				if b.state == WCB_SYN_RECEIVED {
					b.SYNSYNACK()
				} else if b.state == WCB_SYN_SENT {
					b.raddr = incoming.from
					b.SYNACK()
				} else {
					REPLY_RST_TO_ADDRESS(b.udpconn, incoming.header.ack, incoming.from)
					b.rcv_received.Remove(ee)

					b.wcb_errno = syscall.ECONNABORTED
					b.state = WCB_CLOSED
					b.cond.Notify()

					b.mutex.Unlock()
					break
				}
				b.mutex.Unlock()
			}

			if WCPPACK_TEST_FLAG(incoming.header.flag, WCP_FLAG_ACK) {
				b.mutex.Lock()

				switch b.state {
				case WCB_SYN_SENT:
					{
						Assert( UDPADDR_EQUAL(b.raddr,incoming.from) )
						b.state = WCB_ESTABLISHED
						b.cond.Notify()
					}
				case WCB_SYN_RECEIVED:
					{
						b.state = WCB_ESTABLISHED
					}
				case WCB_FIN_WAIT_1:
					{
						b.state = WCB_FIN_WAIT_2
					}
				case WCB_LAST_ACK:
					{
						b.state = WCB_CLOSED
					}
				case WCB_CLOSING:
					{
						b.timer_state = now
						b.state = WCB_TIME_WAIT
					}
				case WCB_ESTABLISHED, WCB_FIN_WAIT_2, WCB_CLOSE_WAIT, WCB_TIME_WAIT:
					{
					}
				default:
					{
						b.mutex.Unlock()
						panic("wcp state logic issue")
					}
				}

				b.mutex.Unlock()
			}

			if WCPPACK_TEST_FLAG(incoming.header.flag, WCP_FLAG_FIN) {
				b.mutex.Lock()

				switch b.state {
				case WCB_ESTABLISHED:
					{
						b.state = WCB_CLOSE_WAIT
						b.r_mutex.Lock()
						b.r_flag |= READ_REMOTE_FIN_RECEIVED
						b.r_flag &= ^READ_REMOTE_FIN_READ_BY_USER

						b.r_cond.Notify()
						b.r_mutex.Unlock()
						b.cond.Notify()

					}
				case WCB_FIN_WAIT_1:
					{
						b.state = WCB_CLOSING
					}
				case WCB_FIN_WAIT_2:
					{
						b.timer_state = now
						b.state = WCB_TIME_WAIT
					}
				default:
					{
						b.state = WCB_CLOSED
						b.wcb_errno = syscall.ECONNABORTED
						REPLY_RST_TO_ADDRESS(b.udpconn, incoming.header.ack, incoming.from)
					}
				}

				b.FINACK()
				b.mutex.Unlock()
			}

			b.rcv_received.Remove(ee)
		}
	}

	if b.rb.Count() == 0 && b.rb_standby.Count() != 0 {
		b.r_mutex.Lock()
		if b.rb.Count() == 0 {
			b.rb, b.rb_standby = b.rb_standby, b.rb

			if b.r_flag&READ_RWND_LESS_THAN_MTU != 0 {
				b.r_flag |= READ_RWND_MORE_THAN_MTU
				b.rcv_info.wnd = b.rb_standby.LeftCapacity()
			}
			b.r_cond.Notify()
		}
		b.r_mutex.Unlock()
	}

	if b.r_flag&(READ_RECV_ERROR|READ_LOCAL_READ_SHUTDOWNED) != 0 {
		b.mutex.Lock()
		b.cond.Notify()
		b.mutex.Unlock()

		b.r_mutex.Lock()
		b.r_cond.Notify()
		b.r_mutex.Unlock()
	}
}

func (b *wcb) check_flights( now uint64) {

	if ((b.wcb_flag&(SND_UNA_UPDATE|SND_FAST_RECOVERED|SND_BIGGEST_SACK_UPDATE)) == 0) &&
			now < (b.snd_last_rto_timer+WCP_RTO_CLOCK_GRANULARITY) {
				return
	}

	b.snd_last_rto_timer = now

	var lost_count uint32
	var max_sent_time uint32

//	var i int = 0

	var ee *list.Element
	for e := b.snd_flights.Front(); e != nil; {
		var pack = e.Value.(*wcbPack)

		//log.Printf("check pack: %d, wcb_flag: %d, left list size: %d, i: %d\n", pack.header.seq, b.wcb_flag, b.snd_flights.Len(), i )
		if (b.wcb_flag&SND_UNA_UPDATE) != 0 && pack.header.seq<b.snd_info.una {
			b.handle_pack_acked(pack, now)

			ee = e
			e = e.Next()
			b.snd_flights.Remove(ee)
			//log.Printf("remove pack: %d by SND_UNA_UPDATE,left list size: %d\n", pack.header.seq, b.snd_flights.Len() )
			continue
		} else {
			e = e.Next()
		}

		var retransmit uint8
		var timediff = uint32(now - pack.sent_ts)
		var skip = int32(b.snd_biggest_ack - pack.header.seq)

		if skip>=1 && timediff >= (b.srtt+b.rttvar>>2) {
			retransmit = 1
		} else if (b.wcb_flag&SND_FAST_RECOVERED) != 0 && timediff >= b.srtt+(b.rttvar>>2) {
			retransmit = 2
		} else if timediff >= b.rto {
			lost_count++
			retransmit = 3

			if (b.wcb_flag&SND_LOST_DETECTED ) !=0 && pack.header.seq>b.snd_lost_biggest_seq {
				b.snd_lost_biggest_seq = pack.header.seq
			}

			if pack.sent_times > max_sent_time {
				max_sent_time = pack.sent_times
			}

		} else {}

		if retransmit > 0 {
			for err := b.send_pack( pack ); err != nil && err != syscall.EAGAIN ;{
				b.s_mutex.Lock()
				b.wcb_errno = err
				b.s_flag |= WRITE_SEND_ERROR
				b.s_mutex.Unlock()

				goto _end_snd_flights_loop
			}

			pack.sent_ts = now
			pack.sent_times++
		}
	}

	b.wcb_flag &= ^(SND_BIGGEST_SACK_UPDATE|SND_UNA_UPDATE|SND_FAST_RECOVERED)

	if lost_count >= WCP_LOST_THRESHOLD || max_sent_time>5 {

		b.rto = MinUint32( (b.rto>>1) + b.rto, WCP_RTO_MAX )

		if b.state == WCB_ESTABLISHED && (uint32(now - b.snd_lost_detected_timer) >= MaxUint32( b.srtt, 30 )) {

			b.snd_lost_detected_timer = now
			b.snd_lost_bigger_than_lost_seq_time = 0

			var half_flight_max = b.snd_nflight_bytes_max>>1

			var new_ssthresh = MaxUint32( half_flight_max, WCP_SND_SSTHRESH_MIN )

			b.snd_lost_cwnd_for_fast_recover_compensation = new_ssthresh - (b.snd_nflight_bytes>>1)
			b.snd_info.ssthresh = MinUint32( new_ssthresh, b.snd_info.ssthresh )

			b.snd_nflight_bytes_max = MaxUint32(b.snd_nflight_bytes_max>>1, b.snd_nflight_bytes)

			b.wcb_flag |= (SND_CWND_SLOW_START|SND_LOST_DETECTED)
			b.wcb_flag &= ^SND_CWND_CONGEST_AVOIDANCE

			b.snd_info.cwnd = WCP_LW*WCP_MTU
		}
	}

	_end_snd_flights_loop:
}

func (b *wcb) check_send( now uint64) {

	if (b.s_flag&WRITE_SEND_ERROR) != 0 {
		b.s_mutex.Unlock()
		return
	}

	if ( b.r_flag&READ_RWND_MORE_THAN_MTU) != 0 && (now-b.r_timer_last_rwnd_update > WCP_RWND_CHECK_GRANULARITY) {
		if b.s_sending_ignore_seq_space.Len() == 0 {
			b.update_rwnd()
		} else {
			e := b.s_sending_ignore_seq_space.Front()
			e.Value.(*wcbPack).header.flag |= WCP_FLAG_WND
		}

		b.r_timer_last_rwnd_update = now
	}

	for b.s_sending_ignore_seq_space.Len() != 0 {
		e := b.s_sending_ignore_seq_space.Front()

		if err := b.send_pack(e.Value.(*wcbPack)); err != nil {
			if err != syscall.EAGAIN {
				b.s_mutex.Lock()
				b.wcb_errno = err
				b.s_flag |= WRITE_SEND_ERROR
				b.s_mutex.Unlock()
			}
			return
		}

		b.s_sending_ignore_seq_space.Remove(e)
	}

_begin_send:
	var ee *list.Element
	for e := b.snd_sending.Front(); e != nil ; {

		var pack = e.Value.(*wcbPack)
		var ntotal_bytes = uint32(pack.header.dlen + WCP_HeaderLen)

		if ( (ntotal_bytes) + b.snd_nflight_bytes) >= MinUint32(b.snd_info.cwnd, b.snd_info.rwnd) {
			//congestion avoidance, ignore
			return ;
		}

		if err := b.send_pack(pack); err != nil {
			if err != syscall.EAGAIN {
				b.s_mutex.Lock()
				b.wcb_errno = err
				b.s_flag |= WRITE_SEND_ERROR
				b.s_mutex.Unlock()
			}
			return
		}

		pack.sent_ts = now
		pack.sent_times = 1

		b.snd_flights.PushBack(pack)
		b.snd_nflight_bytes += ntotal_bytes

		if b.snd_nflight_bytes > b.snd_nflight_bytes_max {
			b.snd_nflight_bytes_max = b.snd_nflight_bytes
		}

		b.snd_info.next++

		if WCPPACK_TEST_FLAG(pack.header.flag, WCP_FLAG_FIN) {
			b.mutex.Lock()

			switch( b.state ) {

			case WCB_ESTABLISHED:
				{
					b.timer_state = now
					b.state = WCB_FIN_WAIT_1

					b.s_mutex.Lock()
					b.s_flag |= WRITE_LOCAL_FIN_SENT
					b.s_mutex.Unlock()
				}
			case WCB_CLOSE_WAIT:
				{
					b.state = WCB_LAST_ACK
					b.timer_state = now
				}
			default:
				{
					b.mutex.Unlock()
					panic("wcp state logic issue")
				}
			}
			b.mutex.Unlock()
		}

		if WCPPACK_TEST_FLAG(pack.header.flag, WCP_FLAG_SYN) {
			b.mutex.Lock()
			if b.state == WCB_SYNING {
				b.state = WCB_SYN_SENT
			}
			b.mutex.Unlock()
		}

		ee = e
		e =e.Next()

		b.snd_sending.Remove(ee)
	}

	for b.s_sending_standby.Len() != 0 {
		b.snd_sending.PushBack(b.s_sending_standby.Front().Value.(*wcbPack))
		b.s_sending_standby.Remove(b.s_sending_standby.Front())
	}

	var nmax_try_bytes = b.snd_info.cwnd - b.snd_nflight_bytes
	if( (b.s_flag&WRITE_LOCAL_FIN_SENT) == 0 && (nmax_try_bytes>= WCP_MTU) ) {
		b.s_mutex.Lock()
		var notify_s_cond bool = false

		for b.sb.Count() > 0 && nmax_try_bytes > 0 {
			var wcbPack= NewWcbPack()

			wcbPack.header.seq = b.snd_info.dsn
			b.snd_info.dsn++

			wcbPack.header.flag = WCP_FLAG_DAT | WCP_FLAG_ACK
			wcbPack.data.Len = uint16(b.sb.Read(wcbPack.data.Buf, WCP_MDU))
			wcbPack.header.dlen = wcbPack.data.Len

			b.snd_sending.PushBack(wcbPack)
			notify_s_cond = true
		}

		if notify_s_cond {
			b.s_cond.Notify()
		}
		b.s_mutex.Unlock()
	}

	if b.snd_sending.Len() > 0 {
		goto _begin_send;
	}
}

func (b *wcb) send_pack( pack *wcbPack ) error {
	pack.header.ack = b.rcv_info.next
	pack.header.wnd = b.rcv_info.wnd
	return INJECT_TO_ADDRESS( b.udpconn, pack, b.raddr )
}

func (b *wcb) listen_handle_incoming() {

	var _len = len(b.received_vec)
	if _len == 0 {
		b.received_vec_mutex.Lock()
		if len(b.received_vec_standby) == 0 {
			b.received_vec_mutex.Unlock()
			return
		} else {
			b.received_vec, b.received_vec_standby = b.received_vec_standby, b.received_vec
		}
		b.received_vec_mutex.Unlock()
	}
	_len = len(b.received_vec)

	var i int
	for ; i<_len; i++ {
		var receivedPack = b.received_vec[i]
		var from = receivedPack.from
		var hash_id = four_tuple_hash(b.laddr, from)

		if _b := _wcp.find_from_four_tuple_hash_map(hash_id) ; _b != nil {
			_b.PACK_RCVD(b.received_vec[i])
			continue;
		}

		{
			b.r_mutex.Lock()
			if b.backlogq.Len() + b.backloglist_pending.Len() == int(b.backlog_size) {
				REPLY_RST_TO_ADDRESS(b.udpconn, receivedPack.header.ack, from)
				continue;
			}
			b.r_mutex.Unlock()
		}

		if WCPPACK_TEST_FLAG(receivedPack.header.flag, WCP_FLAG_RST) {
			continue	//RFC 793: ignore RST for a state in LISTEN
		}

		if !WCPPACK_TEST_FLAG(receivedPack.header.flag, WCP_FLAG_SYN) {
			REPLY_RST_TO_ADDRESS(b.udpconn, receivedPack.header.ack, from)
			continue
		}

		var wcb = NewWCB()
		wcb.socket()

		wcb.wcb_flag |= WCB_FLAG_IS_PASSIVE_OPEN
		wcb.four_tuple_hash_id = hash_id
		wcb.bind(b.laddr)
		wcb.raddr = from
		wcb.udpconn = b.udpconn

		wcb.set_rcv_buffer_size( b.get_rcv_buffer_size() )
		wcb.set_snd_buffer_size( b.get_snd_buffer_size() )

		wcb.SYN_RCVD(receivedPack)

		if _wcp.add_to_four_tuple_hash_map(wcb) != nil {
			wcb.close()
			REPLY_RST_TO_ADDRESS(b.udpconn, receivedPack.header.ack, wcb.raddr)
			continue
		}

		b.r_mutex.Lock()
		b.backloglist_pending.PushBack(wcb)
		b.r_mutex.Unlock()

		_wcp.enqueue_ch_wcb_new(wcb)
	}
	//reset
	b.received_vec = b.received_vec[0:0]
}

func (b *wcb) pump_packs() {
	for {

		var buf = NewPack()
		n, raddr, err := b.udpconn.ReadFrom( buf.Buf )

		if err != nil && err != syscall.EAGAIN {
			b.wcb_errno = err
			b.r_mutex.Lock()
			b.r_flag |= READ_RECV_ERROR
			b.r_mutex.Unlock()
			break
		}

		Assert( err == nil )

		receivedPack, err := WCPPACK_FROM_UDPMESSAGE(buf.Buf, uint16(n))
		Assert( receivedPack != nil )
		Assert( raddr != nil )

		receivedPack.from = raddr.(*net.UDPAddr)

		b.received_vec_mutex.Lock()
		b.received_vec_standby = append(b.received_vec_standby, receivedPack)
		b.received_vec_mutex.Unlock()
	}
}

func (b *wcb) socket() {
	b.init()
	b.fd = make_wcb_fd()
}

func (b *wcb) bind( laddr *net.UDPAddr) {
	b.laddr = laddr
}

func (b *wcb) listen( backlog int) error {
	b.mutex.Lock()
	b.state = WCB_LISTEN
	b.backlog_size = backlog
	b.wcb_flag |= WCB_FLAG_IS_LISTENER
	b.mutex.Unlock()
	return nil
}

func (b *wcb) accept() (conn *WCPConn, err error ) {
_begin_accept:
	b.r_mutex.Lock()
	if b.r_flag&(READ_RECV_ERROR|READ_LOCAL_READ_SHUTDOWNED) != 0 {
		if b.wcb_errno != nil {
			return nil,b.wcb_errno
		}
		return nil, syscall.ECONNABORTED
	}

	if b.backlogq.Len() == 0 {
		b.r_mutex.Unlock()
		b.r_cond.Wait()
		goto _begin_accept
	}

	var e = b.backlogq.Front()
	Assert( e != nil)

	conn = newWCPConn(e.Value.(*wcb))
	b.backlogq.Remove(e)
	b.r_mutex.Unlock()
	return
}

func (b *wcb) connect( raddr *net.UDPAddr) (err error) {
	b.mutex.Lock()
	b.raddr = raddr
	Assert( b.state == WCB_CLOSED)
	{
		b.s_mutex.Lock()
		b.SYN()
		b.s_mutex.Unlock()
	}

	b.state = WCB_SYNING
	b.timer_state = UnixMill()
	b.mutex.Unlock()

	b.cond.Wait()
	b.mutex.Lock()
	//I'm not sure whether go would return from a chan without a definite ch <-
	for b.wcb_errno == nil && b.state != WCB_ESTABLISHED {
		b.cond.Wait()
		b.mutex.Lock()
	}
	b.mutex.Unlock()

	//if no err occur, return nil with b.state == WCB_ESTABLISHED
	err = b.wcb_errno
	return
}

func (b *wcb) shutdown( flag int) (err error) {
	b.mutex.Lock()
	Assert(flag == WCB_SHUTDOWN_RD || flag == WCB_SHUTDOWN_WR || flag == WCB_SHUTDOWN_RDWR)

	err = syscall.ENOTCONN
	if flag&WCB_SHUTDOWN_WR != 0 {
		b.s_mutex.Lock()
		if b.s_flag&WRITE_LOCAL_WRITE_SHUTDOWNED == 0 {
			err = nil
			b.FIN()
			b.s_flag |= WRITE_LOCAL_WRITE_SHUTDOWNED
		}
		b.s_mutex.Unlock()
	}

	if flag&WCB_SHUTDOWN_RD != 0 {
		b.r_mutex.Lock()
		if b.r_flag&READ_LOCAL_READ_SHUTDOWNED == 0 {
			err = nil
			b.r_flag |= READ_LOCAL_READ_SHUTDOWNED
			b.r_cond.Notify()
		}
		b.r_mutex.Unlock()
	}

	b.mutex.Unlock()
	return
}

func (b *wcb) close() (err error) {
	b.mutex.Lock()

	if b.wcb_flag&WCB_FLAG_CLOSED_CALLED != 0 {
		goto _end_close
		return syscall.EALREADY
	}
	b.wcb_flag |= WCB_FLAG_CLOSED_CALLED

	if b.state == WCB_LISTEN {
		b.state = WCB_CLOSED
	}

	if b.state == WCB_SYN_SENT || b.state == WCB_SYNING || b.state == WCB_SYN_RECEIVED {
		b.state = WCB_CLOSED
		if b.wcb_errno == nil {
			b.wcb_errno = syscall.WSAECONNABORTED
		}
	}

	if b.state == WCB_CLOSED {
		b.s_mutex.Lock()
		b.s_flag |= WRITE_LOCAL_WRITE_SHUTDOWNED
		b.s_mutex.Unlock()

		b.r_mutex.Lock()
		b.r_flag |= READ_LOCAL_READ_SHUTDOWNED
		b.r_cond.Notify()
		b.r_mutex.Unlock()
		goto _end_close
	}

	if b.state == WCB_ESTABLISHED ||
		b.state == WCB_CLOSE_WAIT {

		b.s_mutex.Lock()
		if b.s_flag&WRITE_LOCAL_WRITE_SHUTDOWNED == 0 {
			b.FIN()
			b.s_flag |= WRITE_LOCAL_WRITE_SHUTDOWNED
		}
		b.s_mutex.Unlock()

		b.r_mutex.Lock()
		if b.r_flag&READ_LOCAL_READ_SHUTDOWNED == 0 {
			b.r_flag |= READ_LOCAL_READ_SHUTDOWNED
		}
		b.r_cond.Notify()
		b.r_mutex.Unlock()
		goto _end_close
	}

_end_close:
	b.mutex.Unlock()
	return nil
}

func (b *wcb) read( buf []byte) (n int, err error) {

_read_begin:
	b.r_mutex.Lock()

	n = 0
	err = nil
	if (b.r_flag&READ_LOCAL_READ_SHUTDOWNED) != 0 {
		n = 0
		err = syscall.ECONNABORTED
		goto _end_read
	}

	if b.rb.Count() > 0 {
		n = int(b.rb.Read(buf, uint32(len(buf))))
		goto _end_read
	}

	if b.r_flag&READ_REMOTE_FIN_RECEIVED != 0 {
		if b.r_flag&READ_REMOTE_FIN_READ_BY_USER != 0 {
			err = syscall.ECONNRESET
			goto _end_read
		}
		b.r_flag |= READ_REMOTE_FIN_READ_BY_USER
		n = 0
		err = io.EOF
		goto _end_read
	}

	if b.r_flag&READ_RECV_ERROR != 0 {
		Assert( b.wcb_errno != nil )
		err = b.wcb_errno
		goto _end_read
	}

	Assert( b.wcb_errno == nil )

	//WAIT NOTIFY
	b.r_mutex.Unlock()
	b.r_cond.Wait()
	goto _read_begin

_end_read:
	b.r_mutex.Unlock()
	return
}

func (b *wcb) write( buf []byte) (wn int , err error ) {

	var nbuf = uint32(len(buf))
	wn = 0
	err = nil
	var left_c uint32

_write_begin:
	b.s_mutex.Lock()
	if (b.s_flag& (WRITE_SEND_ERROR|WRITE_LOCAL_WRITE_SHUTDOWNED)) != 0 {
		if b.wcb_errno == nil {
			err = syscall.ECONNABORTED
		}
		goto _end_write
	}

	left_c = b.sb.LeftCapacity()
	if left_c < (nbuf - uint32(wn)) && left_c < 2*WCP_MTU {
		b.s_mutex.Unlock()
		b.s_cond.Wait()
		goto _write_begin
	}
	wn += int(b.sb.Write(buf[wn:], (nbuf - uint32(wn))))

_end_write:
	b.s_mutex.Unlock()
	return
}

const(
	WCP_S_IDLE = iota
	WCP_S_RUN
	WCP_S_EXIT
)

const WCP_FD_MAX int = 2048

type WCPConn struct {
	WCB *wcb
}

func newWCPConn(b *wcb ) *WCPConn {
	return &WCPConn{
		WCB:b,
	}
}

type WCPListener struct {
	WCB *wcb
}

func newWCPListener(b *wcb ) *WCPListener {
	return &WCPListener {
		WCB: b,
	}
}

type wcb_map_type map[int]*wcb

var wcb_auto_increment_id int32 = 1
func make_wcb_fd() int {
	return int(atomic.AddInt32(&wcb_auto_increment_id, 1)) % WCP_FD_MAX + 0xFFFFFF
}

type wcp struct {
	mutex sync.RWMutex
	state uint8

	wcb_map_mutex sync.RWMutex
	wcb_map wcb_map_type

	wcb_four_tuple_map_mutex sync.RWMutex
	wcb_four_tuple_map wcb_map_type

	wcb_to_delete_tmp []int

	ch_wcb_new chan *wcb
}

func (p *wcp) find_from_four_tuple_hash_map(hash int ) (b *wcb) {
	p.wcb_four_tuple_map_mutex.RLock()
	b = p.wcb_four_tuple_map[hash]
	p.wcb_four_tuple_map_mutex.RUnlock()
	return
}

func(p *wcp) add_to_four_tuple_hash_map(b *wcb) error {
	p.wcb_four_tuple_map_mutex.Lock()

	if len(p.wcb_four_tuple_map) >= WCP_FD_MAX {
		p.wcb_four_tuple_map_mutex.Unlock()
		return syscall.EMFILE
	}

	Assert( b.four_tuple_hash_id > 0 )

	if p.wcb_four_tuple_map[b.four_tuple_hash_id] != nil {
		p.wcb_four_tuple_map_mutex.Unlock()
		return syscall.EADDRINUSE
	}

	p.wcb_four_tuple_map[b.four_tuple_hash_id] = b
	p.wcb_four_tuple_map_mutex.Unlock()

	return nil
}

func (p *wcp) remove_from_four_tuple_hash_map(b *wcb) error {

	Assert(b.four_tuple_hash_id > 0)
	Assert(b.wcb_flag&WCB_FLAG_IS_PASSIVE_OPEN != 0)
	p.wcb_four_tuple_map_mutex.Lock()

	if p.wcb_four_tuple_map[b.four_tuple_hash_id] == nil {
		p.wcb_four_tuple_map_mutex.Unlock()
		return syscall.EBADF
	}

	delete(p.wcb_four_tuple_map, b.four_tuple_hash_id)
	p.wcb_four_tuple_map_mutex.Unlock()

	return nil
}


func (p *wcp) Start() {
	p.mutex.Lock()
	p.state = WCP_S_RUN

	p.wcb_map = make(wcb_map_type)
	p.wcb_four_tuple_map = make(wcb_map_type)

	p.wcb_to_delete_tmp = make([]int, 0, 1024)

	p.ch_wcb_new = make(chan *wcb, 128)
	p.mutex.Unlock()

	go p.run()
}

func (p *wcp) Stop() {
	p.mutex.Lock()
	p.state = WCP_S_EXIT

	{
		p.wcb_map_mutex.Lock()

		for _, v := range p.wcb_map {
			v.close()
			v.udpconn.Close()
		}

		p.wcb_map = make(wcb_map_type)
		p.wcb_map_mutex.Unlock()
	}

	p.mutex.Unlock()
}

func (p *wcp) enqueue_ch_wcb_new( b *wcb ) {
	Assert( b != nil )
	Assert( b.fd >0 )

	p.ch_wcb_new <- b
}

func (p *wcp) select_ch_wcb_new() {
	select {
	case _nb := <- p.ch_wcb_new:
		{
			Assert( _nb.fd >0 )
			Assert( p.wcb_map[_nb.fd] == nil )

			p.wcb_map_mutex.Lock()
			p.wcb_map[_nb.fd] = _nb
			p.wcb_map_mutex.Unlock()
		}
	default:
		{}
	}
}

func (p *wcp) run() {
	for {
		p.mutex.RLock()
		if p.state != WCP_S_RUN {
			p.mutex.RUnlock()
			return
		}
		p.select_ch_wcb_new()
		p.update()
		p.mutex.RUnlock()
		time.Sleep(time.Microsecond*8)
	}
}

func (p *wcp) update() {

	{
		p.wcb_map_mutex.RLock()
		for k, v := range p.wcb_map {
			var now= UnixMill()
			s := v.Update(now)

			if s == WCB_RECYCLE {
				v.close()
				v.udpconn.Close()
				p.wcb_to_delete_tmp = append(p.wcb_to_delete_tmp, k)
			}
		}
		p.wcb_map_mutex.RUnlock()
	}

	if len( p.wcb_to_delete_tmp ) != 0 {
		p.wcb_map_mutex.Lock()
		for k := range p.wcb_to_delete_tmp {
			delete(p.wcb_map, k)
		}
		p.wcb_to_delete_tmp = p.wcb_to_delete_tmp[0:0]
		p.wcb_map_mutex.Unlock()
	}
}

type myPacketConn struct {
	*net.UDPConn
}
func newMyPacketConn( c *net.UDPConn ) *myPacketConn {
	return &myPacketConn{UDPConn:c}
}
func (c *myPacketConn) WriteTo( b []byte, addr net.Addr ) (int,error) {return c.Write(b) }

func (p *wcp) impl_DialWCP(raddr* net.UDPAddr)(c *WCPConn , err error) {
	if _c, err := net.DialUDP("udp", nil, raddr ) ; err == nil {
		_wcb := NewWCB()
		_wcb.udpconn = newMyPacketConn(_c)
		_wcb.socket()
		_wcb.bind(nil)

		p.enqueue_ch_wcb_new(_wcb)
		go _wcb.pump_packs()

		if err = _wcb.connect(raddr) ; err != nil {
			_wcb.close()
		} else {
			c = newWCPConn(_wcb)
		}
	}
	return
}

func (p *wcp) impl_ListenWCP( laddr* net.UDPAddr ) (l *WCPListener, err error) {

	if _l,err := net.ListenUDP( "udp", laddr ) ; err == nil {
		_wcb := NewWCB()
		_wcb.udpconn = _l
		_wcb.socket()
		_wcb.bind(laddr)

		if err = _wcb.listen(WCP_BACKLOG_DEFAULT); err != nil {
			_wcb.close()
		} else {
			p.wcb_map_mutex.Lock()
			p.wcb_map[_wcb.fd] = _wcb
			p.wcb_map_mutex.Unlock()

			l = newWCPListener(_wcb)
			go _wcb.pump_packs()
		}
	}
	return
}

func (p *WCPListener) impl_AcceptWCP() (*WCPConn, error) {
	return p.WCB.accept()
}

func (p *WCPListener) impl_Close() error {
	return p.WCB.close()
}

var _wcp *wcp
func init() {
	_wcp = &wcp{}
}

func Start() {
	_wcp.Start()
}

func Stop() {
	_wcp.Stop()
}