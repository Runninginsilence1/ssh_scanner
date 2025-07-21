package combiner

import (
	"fmt"
)

func CombineHost(prefix int, port int) string {
	return fmt.Sprintf("192.168.%d.%d", prefix, port)
}
