package wcp

import (
	"fmt"
	"time"
)

func Assert(b_ bool, args ...interface{}) {
	var list []interface{}
	list = append(list, args...)
	if !b_ {
		if len(list) > 1 {
			panic(fmt.Sprintf(list[0].(string), list[1:]...))
		} else if len(list) == 1 {
			panic(list[0].(string))
		} else {
			panic("error")
		}
	}
}

func AbsUint32(op1, op2 uint32) uint32 {
	if v := int32(op1 - op2) ; v > 0{
		return uint32(v)
	}
	return op2-op1
}

func AbsUint64(op1,op2 uint64) uint64{
	if v := int64(op1 - op2) ; v > 0{
		return uint64(v)
	}
	return op2-op1
}

func MaxUint32( op1, op2 uint32 ) (max uint32) {
	max = op1
	if max < op2 {
		max = op2
	}
	return
}

func MinUint32(op1,op2 uint32) (min uint32) {
	min = op1
	if min > op2 {
		min = op2
	}
	return
}

func MaxUint16(op1,op2 uint16) (max uint16) {
	max = op1
	if max < op2 {
		max = op2
	}
	return
}

func MinUint16(op1,op2 uint16) (min uint16) {
	min = op1
	if min > op2 {
		min = op2
	}
	return
}

func UnixNano() uint64 {
	return uint64(time.Now().UnixNano())
}

func UnixMicro() uint64 {
	return UnixNano()/1000
}

func UnixMill() uint64 {
	return UnixNano()/1000000
}

func UnixSec() uint64 {
	return uint64(time.Now().Unix())
}

func ReadU8(b []byte) uint8 {
	return uint8(b[0])
}

func ReadI8(b []byte) int8 {
	return int8(b[0])
}

func ReadU16(b []byte) uint16 {
	_ = b[1]
	return uint16(b[1]) | uint16(b[0])<<8
}

func ReadI16(b []byte) int16 {
	_ = b[1]
	return int16(b[1]) | int16(b[0])<<8
}

func ReadU32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
func ReadI32(b []byte) int32 {
//	return int32(ReadU32(b))
	_ = b[3]
	return int32(b[3]) | int32(b[2])<<8 | int32(b[1])<<16 | int32(b[0])<<24
}

func ReadU64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

func ReadI64(b []byte) int64 {
	_ = b[7]
	return int64(b[7]) | int64(b[6])<<8 | int64(b[5])<<16 | int64(b[4])<<24 |
		int64(b[3])<<32 | int64(b[2])<<40 | int64(b[1])<<48 | int64(b[0])<<56
}

func WriteU8(b []byte, v uint8) {
	b[0] = v
}

func WriteI8(b []byte, v int8) {
	b[0] = byte(v)
}

func WriteU16(b []byte, v uint16) {
	_ = b[1]
	b[0] = byte(v>>8)
	b[1] = byte(v)
}

func WriteI16(b []byte, v int16) {
	WriteU16(b, uint16(v))
}

func WriteU32(b []byte, v uint32) {
	_ = b[3]
	b[0] = byte(v>>24)
	b[1] = byte(v>>16)
	b[2] = byte(v>>8)
	b[3] = byte(v)
}

func WriteI32(b []byte, v int32) {
	WriteU32(b, uint32(v))
}

func WriteU64(b []byte, v uint64) {
	_ = b[7]
	b[0] = byte(v>>56)
	b[1] = byte(v>>48)
	b[2] = byte(v>>40)
	b[3] = byte(v>>32)
	b[4] = byte(v>>24)
	b[5] = byte(v>>16)
	b[6] = byte(v>>8)
	b[7] = byte(v)
}

func WriteI64(b []byte, v int64) {
	WriteU64(b, uint64(v))
}

func WriteBytes(dst []byte, src []byte) uint32{
	return uint32(copy(dst,src))
}

func ReadBytes(dst []byte, src []byte) uint32 {
	return uint32(copy(dst,src))
}

const (
	PACK_MIN_LEFT_CAPACITY    = 128
	PACK_MAX_LEFT_CAPACITY    = (1024 * 1024 * 16)
	PACK_MIN_RIGHT_CAPACITY   = 256
	PACK_MAX_RIGHT_CAPACITY   = (1024 * 1024 * 16)
	PACK_MIN_CAPACITY         = (PACK_MIN_LEFT_CAPACITY + PACK_MIN_RIGHT_CAPACITY)
	PACK_MAX_CAPACITY         = (PACK_MAX_LEFT_CAPACITY + PACK_MAX_RIGHT_CAPACITY)
	PACK_INIT_LEFT_CAPACITY   = PACK_MIN_LEFT_CAPACITY
	PACK_INITRIGHT_CAPACITY   = (1024 * 4)
	PACK_INCREMENT_LEFT_SIZE  = (1024 * 8)
	PACK_INCREMENT_RIGHT_SIZE = (1024 * 8)
)

type Packet struct {
	left_capacity, read_idx, right_capacity, write_idx uint32
	buffer                                             []byte
}

func (pkt *Packet) capacity() uint32 {
	return pkt.left_capacity + pkt.right_capacity
}

func (pkt *Packet) Reset() {
	pkt.read_idx = pkt.left_capacity
	pkt.write_idx = pkt.left_capacity
}

func (pkt *Packet) Len() uint32 {
	return pkt.write_idx - pkt.read_idx
}

func (pkt *Packet) extend_leftbuffer_capacity() {
	Assert(pkt.buffer != nil)
	Assert(pkt.left_capacity+PACK_INCREMENT_LEFT_SIZE <= PACK_MAX_LEFT_CAPACITY)

	pkt.left_capacity += PACK_INCREMENT_LEFT_SIZE
	_new_buffer := make([]byte, pkt.capacity())

	_len := pkt.Len()
	_new_left := pkt.read_idx + PACK_INCREMENT_LEFT_SIZE

	if (_new_left != pkt.read_idx) && (_len > 0) {
		copy(_new_buffer[_new_left:_new_left+_len], pkt.buffer[:])

		pkt.write_idx += PACK_INCREMENT_LEFT_SIZE
		pkt.read_idx = _new_left
		pkt.buffer = _new_buffer
	}
}

func (pkt *Packet) extend_rightbuffer_capacity() {
	Assert(pkt.buffer != nil)
	Assert(pkt.right_capacity+PACK_INCREMENT_RIGHT_SIZE <= PACK_MAX_RIGHT_CAPACITY)

	pkt.right_capacity += PACK_INCREMENT_RIGHT_SIZE

	_new_buffer := make([]byte, pkt.capacity())

	copy(_new_buffer[pkt.read_idx:pkt.read_idx+pkt.Len()], pkt.buffer)
	pkt.buffer = _new_buffer
}

func (pkt *Packet) init_buffer(left, right uint32) {
	pkt.left_capacity = left
	if pkt.left_capacity < PACK_MIN_LEFT_CAPACITY {
		pkt.left_capacity = left
	}

	pkt.right_capacity = right
	if pkt.right_capacity < PACK_MIN_RIGHT_CAPACITY {
		pkt.right_capacity = right
	}

	Assert(pkt.left_capacity <= PACK_MAX_LEFT_CAPACITY)
	Assert(pkt.right_capacity <= PACK_MAX_RIGHT_CAPACITY)

	pkt.buffer = make([]byte, pkt.capacity())
	pkt.Reset()
}

func (pkt *Packet) left_left_capacity() uint32 {
	if pkt.buffer == nil {
		return 0
	}
	return pkt.read_idx
}

func (pkt *Packet) left_right_capacity() uint32 {
	if pkt.buffer == nil {
		return 0
	}
	return pkt.capacity() - pkt.write_idx
}

func NewPacket(right uint32) *Packet {
	var __pkt = &Packet{}
	__pkt.init_buffer(PACK_INIT_LEFT_CAPACITY, right)
	return __pkt
}

func NewPacketWithLeftRight(left uint32, right uint32) *Packet {
	var __pkt = &Packet{}
	__pkt.init_buffer(left, right)
	return __pkt
}

func (pkt *Packet) WriteLeft(b[]byte, len_ uint32) *Packet {
	Assert(pkt.buffer != nil)
	Assert( uint32(len(b)) >= len_ )

	for len_ > pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -= len_
	copy(pkt.buffer[pkt.read_idx:], b)
	return pkt
}

func (pkt *Packet) Write(b []byte, len_ uint32 ) *Packet {
	Assert(pkt.buffer != nil)
	Assert( uint32(len(b)) >= len_ )

	for len_ > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	copy(pkt.buffer[pkt.write_idx:], b)
	pkt.write_idx += len_

	return pkt
}

func (pkt *Packet) Read(b []byte, size uint32) (n uint32) {
	Assert(pkt.buffer != nil)
	Assert( uint32(len(b)) >= size )

	n = pkt.Len()
	if n > size {
		n = size
	}

	copy(b, pkt.buffer[pkt.read_idx:pkt.read_idx+n])
	pkt.read_idx += n

	return
}

func (pkt *Packet) WriteLeftU8( v uint8) *Packet {
	for 1> pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -= 1
	WriteU8(pkt.buffer[pkt.read_idx:],v)
	return pkt
}

func (pkt *Packet) WriteLeftI8(v int8) *Packet {
	for 1>pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -= 1
	WriteI8(pkt.buffer[pkt.read_idx:],v)
	return pkt
}

func (pkt *Packet) WriteLeftU16( v uint16 ) *Packet {
	for 2>pkt.left_left_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	pkt.read_idx -= 2
	WriteU16(pkt.buffer[pkt.read_idx:],v)
	return pkt
}

func (pkt *Packet) WriteLeftI16( v int16) *Packet {
	for 2> pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -= 2
	WriteI16(pkt.buffer[pkt.read_idx:],v)
	return pkt
}

func (pkt *Packet) WriteLeftU32( v uint32) *Packet {
	for 4>pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -= 4
	WriteU32(pkt.buffer[pkt.read_idx:],v)
	return pkt
}

func (pkt *Packet) WriteLeftI32(v int32) *Packet {
	for 4>pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -=4
	WriteI32(pkt.buffer[pkt.read_idx:],v)
	return pkt
}

func (pkt *Packet) WriteLeftU64(v uint64) *Packet {

	for 8>pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -= 8
	WriteU64(pkt.buffer[pkt.read_idx:],v)
	return pkt
}

func (pkt *Packet) WriteLeftI64( v int64) *Packet {
	for 8>pkt.left_left_capacity() {
		pkt.extend_leftbuffer_capacity()
	}

	pkt.read_idx -= 8
	WriteI64(pkt.buffer[pkt.read_idx:],v)
	return pkt
}


func (pkt *Packet) WriteU8 ( v uint8 ) *Packet {

	for 1 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteU8(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 1

	return pkt
}

func (pkt *Packet) WriteI8 ( v int8 ) *Packet {

	for 1 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteI8(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 1

	return pkt
}

func (pkt *Packet) WriteU16 ( v uint16 ) *Packet {

	for 2 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteU16(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 2

	return pkt
}

func (pkt *Packet) WriteI16 ( v int16 ) *Packet {

	for 2 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteI16(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 2

	return pkt
}

func (pkt *Packet) WriteU32 ( v uint32 ) *Packet {

	for 4 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteU32(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 4

	return pkt
}

func (pkt *Packet) WriteI32 ( v int32 ) *Packet {

	for 4 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteI32(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 4

	return pkt
}

func (pkt *Packet) WriteU64 ( v uint64 ) *Packet {

	for 8 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteU64(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 8

	return pkt
}

func (pkt *Packet) WriteI64 ( v int64 ) *Packet {

	for 8 > pkt.left_right_capacity() {
		pkt.extend_rightbuffer_capacity()
	}

	WriteI64(pkt.buffer[pkt.write_idx:], v)
	pkt.write_idx += 8

	return pkt
}

func (pkt *Packet) ReadU8( rt uint8) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 1 <= pkt.Len() )

	rt = ReadU8(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 1
	return
}

func (pkt *Packet) ReadI8( rt int8) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 1 <= pkt.Len() )

	rt = ReadI8(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 1
	return
}

func (pkt *Packet) ReadU16( rt uint16) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 2 <= pkt.Len() )

	rt = ReadU16(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 2
	return
}

func (pkt *Packet) ReadI16( rt int16) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 2 <= pkt.Len() )

	rt = ReadI16(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 2
	return
}

func (pkt *Packet) ReadU32() (rt uint32) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 4 <= pkt.Len() )

	rt = ReadU32(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 4
	return
}

func (pkt *Packet) ReadI32() (rt int32) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 4 <= pkt.Len() )

	rt = ReadI32(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 4
	return
}

func (pkt *Packet) ReadU64() (rt uint64) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 8 <= pkt.Len() )

	rt = ReadU64(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 8
	return
}

func (pkt *Packet) ReadI64()(rt int64) {
	Assert( pkt.buffer != nil )
	Assert( pkt.read_idx + 8 <= pkt.Len() )

	rt = ReadI64(pkt.buffer[pkt.read_idx:])
	pkt.read_idx += 8
	return
}

type BytesRingbuffer struct {
	capacity, begin, end uint32
	buffer               []byte
}

func NewBytesRingBuffer(capacity_ uint32) *BytesRingbuffer {
	var n = capacity_ + 1
	return &BytesRingbuffer{
		capacity: n,
		begin:    0,
		end:      0,
		buffer:   make([]byte, n),
	}
}

func (rb *BytesRingbuffer) Reset() {
	rb.begin = 0
	rb.end = 0
}

func (rb *BytesRingbuffer) IsEmpty() bool {
	return rb.begin == rb.end
}

func (rb *BytesRingbuffer) IsFull() bool {
	return (rb.end+1)%rb.capacity == rb.begin
}

func (rb *BytesRingbuffer) Capacity() uint32 {
	return rb.capacity - 1
}

func (rb *BytesRingbuffer) LeftCapacity() uint32 {
	return rb.Capacity() - rb.Count()
}

func (rb *BytesRingbuffer) Count() uint32 {
	return ((rb.end - rb.begin) + rb.capacity) % rb.capacity
}

func (rb *BytesRingbuffer) skip(s uint32) {
	Assert(s <= rb.Count())

	rb.begin = (rb.begin + s) % rb.capacity

	if rb.IsEmpty() {
		rb.Reset()
	}
}

func (rb *BytesRingbuffer) Read(b []byte, size uint32) (n uint32) {
	Assert( uint32(len(b)) >= size )

	n = rb.Count()
	if n == 0 {
		return
	}

	if n > size {
		n = size
	}

	if rb.end > rb.begin {
		copy(b, rb.buffer[rb.begin:rb.begin+n])
	} else {

		tail_c := rb.capacity - rb.begin

		if tail_c >= n {
			copy(b, rb.buffer[rb.begin:rb.begin+n])
		} else {
			copy(b, rb.buffer[rb.begin:rb.begin+tail_c])
			copy(b[:tail_c], rb.buffer[:n-tail_c])
		}
	}

	rb.skip(n)
	return
}

func (rb *BytesRingbuffer) Write(b []byte, len_ uint32) (n uint32) {
	Assert( uint32(len(b)) >= len_ )

	n = rb.LeftCapacity()
	if n == 0 {
		return
	}

	if rb.end == rb.begin {
		rb.end = 0
		rb.begin = 0
	}

	if n > len_ {
		n = len_
	}

	if rb.end <= rb.begin {
		copy(rb.buffer[rb.end:], b)
		rb.end = (rb.end + n) % rb.capacity
	} else {
		tail_s := rb.capacity - rb.end

		if tail_s >= n {
			copy(rb.buffer[rb.end:], b)
			rb.end = (rb.end + n) % rb.capacity
		} else {
			copy(rb.buffer[rb.end:], b[:tail_s])
			rb.end = n - tail_s
			copy(rb.buffer[:], b[tail_s:])
		}
	}

	return
}

type Condition struct {
	ch chan struct{}
}

func NewCondition() *Condition {
	return &Condition{
		ch: make(chan struct{}),
	}
}

func (cond *Condition) Wait() {
	 <- cond.ch
}

func (cond *Condition) Notify() {
	select {
		case cond.ch <- struct{}{}:
	default:
	}
}

func (cond *Condition) Close() {
	close(cond.ch)
}