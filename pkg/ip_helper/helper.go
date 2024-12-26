package ip_helper

import (
	"strings"

	"github.com/spf13/cast"
)

func GetIpLast(ip string) int {
	ipArr := strings.Split(ip, ".")
	n := len(ipArr)
	return cast.ToInt(ipArr[n-1])
}
