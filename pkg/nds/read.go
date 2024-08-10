package nds

import (
	"bytes"
	"fmt"
)

const (
	_ uint8 = iota
	ConfigName
	Data
)

func Nds2PB(bin []byte) (string, []byte, error) {
	reader := bytes.NewReader(bin)

	seq, _ := reader.ReadByte()
	if seq != ConfigName {
		return "", nil, fmt.Errorf("expect 1, got %d", seq)
	}

	var profileBytes []byte
	for {
		b, err := reader.ReadByte()
		if err != nil || b == 0 {
			break
		}
		profileBytes = append(profileBytes, b)
	}

	seq, _ = reader.ReadByte()
	if seq != Data {
		return "", nil, fmt.Errorf("expect 2, got %d", seq)
	}

	pb := make([]byte, reader.Len())
	reader.Read(pb)

	return string(profileBytes), pb, nil
}
