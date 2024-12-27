package dumper

import (
	"errors"
	"strings"
)

type Type int

const (
	Console Type = iota
	JSON
)

var typeList = [...]string{"console", "json"}

var ErrTypeNotSupported = errors.New("output type not supported")

func GetType(t string) (Type, error) {
	switch t {
	case typeList[0]:
		return Console, nil
	case typeList[1]:
		return JSON, nil
	default:
		return Console, ErrTypeNotSupported
	}
}

func GetAllTypeString() string {
	return "[" + strings.Join(typeList[:], ", ") + "]"
}
