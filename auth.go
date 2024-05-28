package socks5_protocol

import (
	"io"
)

type AuthUserPasswordReq struct {
	Ver    Socks5Version
	Ulen   uint8
	Uname  string
	Plen   uint8
	Passwd string
}

func (req *AuthUserPasswordReq) Serialize() []byte {
	data := []byte{byte(req.Ver), req.Ulen}
	data = append(data, []byte(req.Uname)...)
	data = append(data, req.Plen)
	data = append(data, []byte(req.Passwd)...)
	return data
}

func (req *AuthUserPasswordReq) UnSerialize(data []byte) {
	req.Ver = Socks5Version(data[0])
	req.Ulen = data[1]
	req.Uname = string(data[2 : 2+req.Ulen])
	req.Plen = data[2+req.Ulen]
	req.Passwd = string(data[3+req.Ulen : 3+req.Ulen+req.Plen])
}

func (req *AuthUserPasswordReq) ReadIO(reader io.Reader) error {
	header := make([]byte, 2)
	_, err := reader.Read(header)
	if err != nil {
		return err
	}

	header = append(header, make([]byte, header[1]+1)...)
	_, err = reader.Read(header[2:])
	if err != nil {
		return err
	}
	// read passwd
	header = append(header, make([]byte, header[2+header[1]])...)
	_, err = reader.Read(header[3+header[1]:])
	if err != nil {
		return err
	}

	req.UnSerialize(header)
	return nil
}

// WriteIO write to io.Writer
func (req *AuthUserPasswordReq) WriteIO(writer io.Writer) error {
	data := req.Serialize()
	_, err := writer.Write(data)
	return err
}

type AuthUserPasswordResp struct {
	Ver    Socks5Version
	Status byte
}

func (resp *AuthUserPasswordResp) Serialize() []byte {
	return []byte{byte(resp.Ver), resp.Status}
}

func (resp *AuthUserPasswordResp) UnSerialize(data []byte) {
	resp.Ver = Socks5Version(data[0])
	resp.Status = data[1]
}

func (resp *AuthUserPasswordResp) ReadIO(reader io.Reader) error {
	header := make([]byte, 2)
	_, err := reader.Read(header)
	if err != nil {
		return err
	}

	resp.UnSerialize(header)
	return nil
}

// WriteIO write to io.Writer
func (resp *AuthUserPasswordResp) WriteIO(writer io.Writer) error {
	data := resp.Serialize()
	_, err := writer.Write(data)
	return err
}
