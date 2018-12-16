package lib

type filterInfo struct {
	Port    []int
	Process []string
	File    []string
}

var filter filterInfo

const (
	fileSize int64 = 20480000
	UDP      uint8 = 17
	TCP      uint8 = 6
)
