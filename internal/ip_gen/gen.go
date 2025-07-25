package ip_gen

import "fmt"

func GetIp(prefix int, index int) string {
	host := fmt.Sprintf("192.168.%v.%v", prefix, index)
	return host
}

func GetAddr(prefix int, index int, port int) string {
	host := fmt.Sprintf("192.168.%v.%v:%d", prefix, index, port)
	return host
}

func GetSshAddr(prefix int, index int) string {
	host := fmt.Sprintf("192.168.%v.%v:22", prefix, index)
	return host
}
