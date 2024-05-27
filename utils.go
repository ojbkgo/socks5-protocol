package socks5_protocol

import (
	"fmt"
)

func SerializeIPv4(addr string) []byte {
	data := make([]byte, 0, 4)
	for _, v := range addr {
		data = append(data, byte(v))
	}
	return data
}

func UnSerializeIPv4(data []byte) string {
	var addr string

	for i := 0; i < 4; i++ {
		addr += fmt.Sprintf("%d", data[i])
		if i < 3 {
			addr += "."
		}
	}
	return addr
}

func SerializeIPv6(addr string) []byte {
	// 16进制 2001:0db8:85a3:0000:0000:8a2e:0370:7334
	data := make([]byte, 0, 16)
	for _, v := range addr {
		data = append(data, byte(v))
	}
	return data
}

func UnSerializeIPv6(data []byte) string {
	var addr string

	for i := 0; i < 16; i += 4 {
		// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
		addr += fmt.Sprintf("%x", data[i])
		addr += fmt.Sprintf("%x", data[i+1])
		addr += fmt.Sprintf("%x", data[i+2])
		addr += fmt.Sprintf("%x", data[i+3])
		if i < 12 {
			addr += ":"
		}
	}
	return addr
}
