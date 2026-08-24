package state

var (
	initializedKey   = []byte{}
	blockPrefix      = []byte{0x00}
	configKey        = []byte{0x01}
	assetPrefix      = []byte{0x10}
	accountPrefix    = []byte{0x11}
	nullifierPrefix  = []byte{0x12}
	operationPrefix  = []byte{0x13}
	transitionPrefix = []byte{0x14}
)

func flatten(slices ...[]byte) []byte {
	size := 0
	for _, slice := range slices {
		size += len(slice)
	}
	result := make([]byte, 0, size)
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}
