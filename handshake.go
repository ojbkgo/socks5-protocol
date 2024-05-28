package socks5_protocol

import (
	"io"
)

type HandshakeReq struct {
	Ver      Socks5Version
	NMethods uint8
	Methods  []Socks5Method
}

func (req *HandshakeReq) Serialize() []byte {
	data := []byte{byte(req.Ver), req.NMethods}
	for _, method := range req.Methods {
		data = append(data, byte(method))
	}
	return data
}

func (req *HandshakeReq) UnSerialize(data []byte) {
	req.Ver = Socks5Version(data[0])
	req.NMethods = data[1]
	req.Methods = make([]Socks5Method, req.NMethods)
	for i := 0; i < int(req.NMethods); i++ {
		req.Methods[i] = Socks5Method(data[2+i])
	}
}

func (req *HandshakeReq) ReadIO(reader io.Reader) error {
	header := make([]byte, 2)
	_, err := reader.Read(header)
	if err != nil {
		return err
	}
	// read methods
	header = append(header, make([]byte, header[1])...)
	_, err = reader.Read(header[2:])
	if err != nil {
		return err
	}

	req.UnSerialize(header)
	return nil
}

// WriteIO write to io.Writer
func (req *HandshakeReq) WriteIO(writer io.Writer) error {
	data := req.Serialize()
	_, err := writer.Write(data)
	return err
}

type HandshakeResp struct {
	Ver    Socks5Version
	Method Socks5Method
}

func (resp *HandshakeResp) Serialize() []byte {
	return []byte{byte(resp.Ver), byte(resp.Method)}
}

func (resp *HandshakeResp) UnSerialize(data []byte) {
	resp.Ver = Socks5Version(data[0])
	resp.Method = Socks5Method(data[1])
}

func (resp *HandshakeResp) ReadIO(reader io.Reader) error {
	header := make([]byte, 2)
	_, err := reader.Read(header)
	if err != nil {
		return err
	}

	resp.UnSerialize(header)

	return nil
}

// WriteIO write to io.Writer
func (resp *HandshakeResp) WriteIO(writer io.Writer) error {
	data := resp.Serialize()
	_, err := writer.Write(data)
	return err
}
