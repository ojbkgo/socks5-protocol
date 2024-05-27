package socks5_protocol

type Socks5Version byte

const (
	Socks5Version5 Socks5Version = 0x05
)

type Socks5Method byte

const (
	Socks5MethodNoAuth       Socks5Method = 0x00
	Socks5MethodGssapi       Socks5Method = 0x01
	Socks5MethodUserPass     Socks5Method = 0x02
	Socks5MethodNoAcceptable Socks5Method = 0xff
)

type Socks5Cmd byte

const (
	Socks5CmdConnect      Socks5Cmd = 0x01
	Socks5CmdBind         Socks5Cmd = 0x02
	Socks5CmdUdpAssociate Socks5Cmd = 0x03
)

type Socks5AddrType byte

const (
	Socks5AddrTypeIPv4       Socks5AddrType = 0x01
	Socks5AddrTypeDomainName Socks5AddrType = 0x03
	Socks5AddrTypeIPv6       Socks5AddrType = 0x04
)

func IsAllowedAddrType(atyp Socks5AddrType) bool {
	switch atyp {
	case Socks5AddrTypeIPv4, Socks5AddrTypeDomainName, Socks5AddrTypeIPv6:
		return true
	}
	return false
}

type Socks5Rep byte

const (
	Socks5RepSuccess                 Socks5Rep = 0x00
	Socks5RepGeneralFailure          Socks5Rep = 0x01
	Socks5RepConnectionNotAllowed    Socks5Rep = 0x02
	Socks5RepNetworkUnreachable      Socks5Rep = 0x03
	Socks5RepHostUnreachable         Socks5Rep = 0x04
	Socks5RepConnectionRefused       Socks5Rep = 0x05
	Socks5RepTTLExpired              Socks5Rep = 0x06
	Socks5RepCommandNotSupported     Socks5Rep = 0x07
	Socks5RepAddressTypeNotSupported Socks5Rep = 0x08
)

var (
	RepMessageMap = map[Socks5Rep]string{
		Socks5RepSuccess:                 "Success",
		Socks5RepGeneralFailure:          "General failure",
		Socks5RepConnectionNotAllowed:    "Connection not allowed by ruleset",
		Socks5RepNetworkUnreachable:      "Network unreachable",
		Socks5RepHostUnreachable:         "Host unreachable",
		Socks5RepConnectionRefused:       "Connection refused",
		Socks5RepTTLExpired:              "TTL expired",
		Socks5RepCommandNotSupported:     "Command not supported",
		Socks5RepAddressTypeNotSupported: "Address type not supported",
	}
)

func GetRepMessage(rep Socks5Rep) string {
	if message, ok := RepMessageMap[rep]; ok {
		return message
	}
	return "Unknown error"
}

const (
	Socks5Reserved byte = 0x00
)

type Socks5AuthStatus byte

const (
	Socks5AuthSuccess Socks5AuthStatus = 0x00
	Socks5AuthFailure Socks5AuthStatus = 0x01
)
