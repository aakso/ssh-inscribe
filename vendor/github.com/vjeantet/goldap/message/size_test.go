package message

import (
	"testing"
)

func TestSizeLDAPMessage(t *testing.T) {

	var testData = getLDAPMessageTestData()
	for i, test := range testData {
		message, err := ReadLDAPMessage(&test.bytes)
		if err != nil {
			t.Errorf("#%d error at offset %d (%s): %s", i, test.bytes.offset, test.bytes.DumpCurrentBytes(), err)
		}
		size := message.size()
		expected := len(test.bytes.bytes)
		if size != expected {
			t.Errorf("#%d: wrong size, GOT: %d, EXPECTED: %d", i, size, expected)
		}
	}
}

type tagAndLengthTestData struct {
	tag          int
	length       int
	expectedSize int
}

func getSizeTagAndLengthTestData() (ret []tagAndLengthTestData) {
	return []tagAndLengthTestData{
		// Length between 0 and 127 are encoded on one byte
		{
			tag:          tagSequence,
			length:       0,
			expectedSize: 2,
		},
		{
			tag:          tagSequence,
			length:       127,
			expectedSize: 2,
		},
		// Length between 128 and 255 are encoded on two bytes
		{
			tag:          tagSequence,
			length:       128,
			expectedSize: 3,
		},
		{
			tag:          tagSequence,
			length:       255,
			expectedSize: 3,
		},
		// Length between 256 (2^8) and 65535 (2^16-1) are encoded on three bytes
		{
			tag:          tagSequence,
			length:       256,
			expectedSize: 4,
		},
		{
			tag:          tagSequence,
			length:       65535,
			expectedSize: 4,
		},
		// Length between 65536 (2^16) and 16777215 (2^24-1) and 255 are encoded on two bytes
		{
			tag:          tagSequence,
			length:       65536,
			expectedSize: 5,
		},
		{
			tag:          tagSequence,
			length:       16777215,
			expectedSize: 5,
		},
	}
}
func TestSizeTagAndLength(t *testing.T) {
	for i, test := range getSizeTagAndLengthTestData() {
		size := sizeTagAndLength(test.tag, test.length)
		if test.expectedSize != size {
			t.Errorf("#%d: wrong size, GOT: %d, EXPECTED: %d", i, size, test.expectedSize)
		}
	}

}
