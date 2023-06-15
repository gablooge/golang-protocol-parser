package streams

import (
	"strconv"
	"strings"
)

func BitToByte(bit []int) byte {
	strSlice := make([]string, len(bit))

	for i, num := range bit {
		strSlice[i] = strconv.Itoa(num)
	}

	str := strings.Join(strSlice, "")
	var result byte

	for i := 0; i < len(str); i++ {
		bit := str[i] - '0'
		result = result<<1 | bit
	}
	return result
}

func BinaryToDecimal(binary []int) int {
	decimal := 0
	for i := len(binary) - 1; i >= 0; i-- {
		decimal += binary[i] << (len(binary) - 1 - i)
	}

	return decimal
}

func bytesToInt(bytes []byte) int {
	var result int
	for _, b := range bytes {
		result = (result << 8) + int(b)
	}

	return result
}
