/*
Copyright (C) 2025 by dyhkwong

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

package juicity

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

var (
	_ network.NetPacketConn = (*clientPacketConn)(nil)
)

type clientPacketConn struct {
	*clientConn
}

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (destination metadata.Socksaddr, err error) {
	destination, err = AddressSerializer.ReadAddrPort(c.clientConn)
	if err != nil {
		return
	}
	var length uint16
	err = binary.Read(c.clientConn, binary.BigEndian, &length)
	if err != nil {
		return
	}
	_, err = buffer.ReadFullFrom(c.clientConn, int(length))
	return
}

func (c *clientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var destination metadata.Socksaddr
	destination, err = AddressSerializer.ReadAddrPort(c.clientConn)
	if err != nil {
		return
	}
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	var length uint16
	err = binary.Read(c.clientConn, binary.BigEndian, &length)
	if err != nil {
		return
	}
	if len(p) < int(length) {
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(c.clientConn, p[:length])
	return
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination metadata.Socksaddr) (err error) {
	defer buffer.Release()
	newBuffer := buf.NewSize(2 + AddressSerializer.AddrPortLen(destination) + buffer.Len())
	defer newBuffer.Release()
	err = AddressSerializer.WriteAddrPort(newBuffer, destination)
	if err != nil {
		return
	}
	err = binary.Write(newBuffer, binary.BigEndian, uint16(buffer.Len()))
	if err != nil {
		return
	}
	_, err = newBuffer.Write(buffer.Bytes())
	if err != nil {
		return
	}
	_, err = c.clientConn.Write(newBuffer.Bytes())
	return
}

func (c *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	destination := metadata.SocksaddrFromNet(addr)
	newBuffer := buf.NewSize(2 + AddressSerializer.AddrPortLen(destination) + len(p))
	defer newBuffer.Release()
	err = AddressSerializer.WriteAddrPort(newBuffer, destination)
	if err != nil {
		return
	}
	err = binary.Write(newBuffer, binary.BigEndian, uint16(len(p)))
	if err != nil {
		return
	}
	_, err = newBuffer.Write(p)
	if err != nil {
		return
	}
	_, err = c.clientConn.Write(newBuffer.Bytes())
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
