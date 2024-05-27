package socks5_protocol

import (
	"io"
)

type Socks5UdpPackage struct {
	Rsv  [2]byte
	Frag byte
	Atyp Socks5AddrType
	Addr Socks5Addr
	Data []byte // 前两个字节表示长度，后续为数据
}

func (req *Socks5UdpPackage) Serialize() []byte {
	data := []byte{
		req.Rsv[0],
		req.Rsv[1],
		req.Frag,
		byte(req.Atyp),
	}
	switch req.Atyp {
	case Socks5AddrTypeIPv4:
		data = append(data, SerializeIPv4(req.Addr.Addr)...)
		data = append(data, byte(req.Addr.Port>>8), byte(req.Addr.Port))
	case Socks5AddrTypeIPv6:
		data = append(data, SerializeIPv6(req.Addr.Addr)...)
		data = append(data, byte(req.Addr.Port>>8), byte(req.Addr.Port))
	case Socks5AddrTypeDomainName:
		data = append(data, byte(len(req.Addr.Addr)))
		data = append(data, []byte(req.Addr.Addr)...)
		data = append(data, byte(req.Addr.Port>>8), byte(req.Addr.Port))
	}
	// length
	data = append(data, byte(len(req.Data)>>8), byte(len(req.Data)))
	data = append(data, req.Data...)
	return data
}

func (req *Socks5UdpPackage) UnSerialize(data []byte) {
	req.Rsv[0] = data[0]
	req.Rsv[1] = data[1]
	req.Frag = data[2]
	req.Atyp = Socks5AddrType(data[3])

	switch req.Atyp {
	case Socks5AddrTypeIPv4:
		req.Addr.Addr = UnSerializeIPv4(data[4:8])
		req.Addr.Port = uint16(data[8])<<8 | uint16(data[9])
		// data 字段 2 字节长度
		req.Data = data[12 : 12+uint16(data[10])<<8|uint16(data[11])]

	case Socks5AddrTypeIPv6:
		req.Addr.Addr = UnSerializeIPv6(data[4:20])
		req.Addr.Port = uint16(data[20])<<8 | uint16(data[21])
		req.Data = data[24 : 24+uint16(data[22])<<8|uint16(data[23])]

	case Socks5AddrTypeDomainName:
		req.Addr.Addr = string(data[5 : 5+data[4]])
		offset := 5 + data[4]
		req.Addr.Port = uint16(data[offset])<<8 | uint16(data[offset+1])
		req.Data = data[offset+2 : uint16(offset+2)+uint16(data[offset])<<8|uint16(data[offset+1])]
	}
}

func (req *Socks5UdpPackage) ReadIO(reader io.Reader) error {
	header := make([]byte, 4)
	_, err := reader.Read(header)
	if err != nil {
		return err
	}

	switch Socks5AddrType(header[3]) {
	case Socks5AddrTypeIPv4:
		header = append(header, make([]byte, 4+2)...)
	case Socks5AddrTypeIPv6:
		header = append(header, make([]byte, 16+2)...)
	case Socks5AddrTypeDomainName:
		header = append(header, make([]byte, 1+header[4]+2)...)
	}

	_, err = reader.Read(header[4:])
	if err != nil {
		return err
	}

	// read data
	header = append(header, make([]byte, 2)...)
	_, err = reader.Read(header[len(header)-1:])
	if err != nil {
		return err
	}
	offset := len(header)

	// read data
	header = append(header, make([]byte, uint16(header[len(header)-2])<<8|uint16(header[len(header)-1]))...)
	_, err = reader.Read(header[offset:])
	if err != nil {
		return err
	}

	req.UnSerialize(header)
	return nil
}
