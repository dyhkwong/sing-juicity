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
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

var (
	_ network.NetPacketConn = (*clientPacketConn)(nil)
	_ network.EarlyConn     = (*clientPacketConn)(nil)
	_ network.FrontHeadroom = (*clientPacketConn)(nil)
)

type clientPacketConn struct {
	*clientConn
}

func (c *clientPacketConn) FrontHeadroom() int {
	if c.clientConn.requestWritten {
		return metadata.MaxSocksaddrLength + 2
	}
	return 1 + metadata.MaxSocksaddrLength + metadata.MaxSocksaddrLength + 2
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
	buffer := buf.With(p)
	var destination metadata.Socksaddr
	destination, err = c.ReadPacket(buffer)
	if err != nil {
		return
	}
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	n = buffer.Len()
	return
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination metadata.Socksaddr) (err error) {
	defer buffer.Release()
	bufferLen := buffer.Len()
	header := buf.With(buffer.ExtendHeader(metadata.SocksaddrSerializer.AddrPortLen(destination) + 2))
	err = metadata.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return
	}
	err = binary.Write(header, binary.BigEndian, uint16(bufferLen))
	if err != nil {
		return
	}
	_, err = c.clientConn.Write(buffer.Bytes())
	return
}

func (c *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), metadata.SocksaddrFromNet(addr))
}

func (c *clientPacketConn) Upstream() any {
	return c.clientConn
}
