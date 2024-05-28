package socks5_protocol

import (
	"io"
)

type Socks5CmdRequest struct {
	Ver  Socks5Version
	Cmd  Socks5Cmd
	Rsv  byte
	Atyp Socks5AddrType
	Addr Socks5Addr
}

func (req *Socks5CmdRequest) Serialize() []byte {
	data := []byte{
		byte(req.Ver),
		byte(req.Cmd),
		req.Rsv,
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

	return data
}

func (req *Socks5CmdRequest) UnSerialize(data []byte) {
	req.Ver = Socks5Version(data[0])
	req.Cmd = Socks5Cmd(data[1])
	req.Rsv = data[2]
	req.Atyp = Socks5AddrType(data[3])

	switch req.Atyp {
	case Socks5AddrTypeIPv4:
		req.Addr.Addr = UnSerializeIPv4(data[4:8])
		req.Addr.Port = uint16(data[8])<<8 | uint16(data[9])
	case Socks5AddrTypeIPv6:
		req.Addr.Addr = UnSerializeIPv6(data[4:20])
		req.Addr.Port = uint16(data[20])<<8 | uint16(data[21])
	case Socks5AddrTypeDomainName:
		req.Addr.Addr = string(data[5 : 5+data[4]])
		req.Addr.Port = uint16(data[5+data[4]])<<8 | uint16(data[5+data[4]+1])
	}
}

func (req *Socks5CmdRequest) ReadIO(reader io.Reader) error {
	// 根据类型读取
	header := make([]byte, 4)
	_, err := reader.Read(header)
	if err != nil {
		return err
	}

	switch Socks5AddrType(header[3]) {
	case Socks5AddrTypeIPv4:
		header = append(header, make([]byte, 4+2)...)
		// read remain
		_, err = reader.Read(header[4:])
	case Socks5AddrTypeIPv6:
		header = append(header, make([]byte, 16+2)...)
		// read remain
		_, err = reader.Read(header[4:])
	case Socks5AddrTypeDomainName:
		// 读取长度
		tempBuf := make([]byte, 1)
		_, err = reader.Read(tempBuf)
		if err != nil {
			return err
		}
		header = append(header, tempBuf[0])
		header = append(header, make([]byte, tempBuf[0]+2)...)
		// read remain
		_, err = reader.Read(header[5:])
	}

	if err != nil {
		return err
	}

	req.UnSerialize(header)
	return nil
}

// WriteIO write to io.Writer
func (req *Socks5CmdRequest) WriteIO(writer io.Writer) error {
	data := req.Serialize()
	_, err := writer.Write(data)
	return err
}

type Socks5CmdConnectResponse struct {
	Ver  Socks5Version
	Rep  Socks5Rep
	Rsv  byte
	Atyp Socks5AddrType
	Addr Socks5Addr
}

func (resp *Socks5CmdConnectResponse) Serialize() []byte {
	data := []byte{
		byte(resp.Ver),
		byte(resp.Rep),
		resp.Rsv,
		byte(resp.Atyp),
	}
	switch resp.Atyp {
	case Socks5AddrTypeIPv4:
		data = append(data, SerializeIPv4(resp.Addr.Addr)...)
		data = append(data, byte(resp.Addr.Port>>8), byte(resp.Addr.Port))
	case Socks5AddrTypeIPv6:
		data = append(data, SerializeIPv6(resp.Addr.Addr)...)
		data = append(data, byte(resp.Addr.Port>>8), byte(resp.Addr.Port))
	case Socks5AddrTypeDomainName:
		data = append(data, byte(len(resp.Addr.Addr)))
		data = append(data, []byte(resp.Addr.Addr)...)
		data = append(data, byte(resp.Addr.Port>>8), byte(resp.Addr.Port))
	}

	return data
}

func (resp *Socks5CmdConnectResponse) UnSerialize(data []byte) {
	resp.Ver = Socks5Version(data[0])
	resp.Rep = Socks5Rep(data[1])
	resp.Rsv = data[2]
	resp.Atyp = Socks5AddrType(data[3])

	switch resp.Atyp {
	case Socks5AddrTypeIPv4:
		resp.Addr.Addr = UnSerializeIPv4(data[4:8])
		resp.Addr.Port = uint16(data[8])<<8 | uint16(data[9])
	case Socks5AddrTypeIPv6:
		resp.Addr.Addr = UnSerializeIPv6(data[4:20])
		resp.Addr.Port = uint16(data[20])<<8 | uint16(data[21])
	case Socks5AddrTypeDomainName:
		resp.Addr.Addr = string(data[5 : 5+data[4]])
		resp.Addr.Port = uint16(data[5+data[4]])<<8 | uint16(data[5+data[4]+1])
	}
}

func (resp *Socks5CmdConnectResponse) ReadIO(reader io.Reader) error {
	// 根据类型读取
	header := make([]byte, 4)
	_, err := reader.Read(header)
	if err != nil {
		return err
	}

	switch Socks5AddrType(header[3]) {
	case Socks5AddrTypeIPv4:
		header = append(header, make([]byte, 4+2)...)
		// read remain
		_, err = reader.Read(header[4:])
	case Socks5AddrTypeIPv6:
		header = append(header, make([]byte, 16+2)...)
		// read remain
		_, err = reader.Read(header[4:])
	case Socks5AddrTypeDomainName:
		// 读取长度
		tempBuf := make([]byte, 1)
		_, err = reader.Read(tempBuf)
		if err != nil {
			return err
		}
		header = append(header, tempBuf[0])
		header = append(header, make([]byte, tempBuf[0]+2)...)
		// read remain
		_, err = reader.Read(header[5:])
	}

	if err != nil {
		return err
	}

	resp.UnSerialize(header)
	return nil
}

// WriteIO write to io.Writer
func (resp *Socks5CmdConnectResponse) WriteIO(writer io.Writer) error {
	data := resp.Serialize()
	_, err := writer.Write(data)
	return err
}
