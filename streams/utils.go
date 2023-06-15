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

func ByteToBits(b byte) []int {
	totalBits := 8
	bits := make([]int, totalBits)

	for i := 0; i < 8; i++ {
		bit := (b >> uint(i)) & 1
		bits[7-i] = int(bit)
	}

	return bits
}

func BinaryToDecimal(binary []int) int {
	decimal := 0
	for i := len(binary) - 1; i >= 0; i-- {
		decimal += binary[i] << (len(binary) - 1 - i)
	}

	return decimal
}

func BytesToInt(bytes []byte) int {
	var result int
	maxBitTotal := 8

	for _, b := range bytes {
		result = (result << maxBitTotal) + int(b)
	}

	return result
}
