package message

import (
	"reflect"
	"testing"
)

func TestReadPrimitiveSubBytesTestData(t *testing.T) {
	for i, test := range PrimitiveSubBytesTestData() {
		value, err := test.bytes.ReadPrimitiveSubBytes(test.class, test.tag, test.typeTag)
		if err != nil {
			t.Errorf("#%d failed: %s", i+1, err)
		} else if !reflect.DeepEqual(test.value, value) {
			t.Errorf("#%d: Wrong value %#v, got %#v", i+1, test.value, value)
		} else if test.offset != test.bytes.offset {
			t.Errorf("#%d: Wrong Offset, value %#v, got %#v", i+1, test.offset, test.bytes.offset)
		}
	}
}

func TestSizePrimitiveSubBytesTestData(t *testing.T) {
	for i, test := range PrimitiveSubBytesTestData() {
		value, err := test.bytes.ReadPrimitiveSubBytes(test.class, test.tag, test.typeTag)
		if err != nil {
			t.Errorf("#%d failed: %s", i+1, err)
		} else if !reflect.DeepEqual(test.value, value) {
			t.Errorf("#%d: Wrong value %#v, got %#v", i+1, test.value, value)
		} else if test.offset != test.bytes.offset {
			t.Errorf("#%d: Wrong Offset, value %#v, got %#v", i+1, test.offset, test.bytes.offset)
		}
	}
}

func NewInt(value int) (ret *int) {
	ret = &value
	return
}

type PrimitiveSubBytesTestSingleData struct {
	bytes   Bytes       // Input
	class   int         // Expected class
	tag     int         // Expected tag
	typeTag int         // Expected type
	value   interface{} // Expected output
	offset  int         // Expected offset after processing
}

func PrimitiveSubBytesTestData() []PrimitiveSubBytesTestSingleData {

	return []PrimitiveSubBytesTestSingleData{
		// Test 1
		{
			bytes: Bytes{
				offset: 0,
				bytes:  []byte{0x02, 0x01, 0x09},
			},
			class:   classUniversal,
			tag:     tagInteger,
			typeTag: tagInteger,
			value:   int32(0x09),
			offset:  3,
		},
		// Test 2
		{
			bytes: Bytes{
				offset: 0,
				bytes:  []byte{0x02, 0x02, 0x09, 0x87},
			},
			class:   classUniversal,
			tag:     tagInteger,
			typeTag: tagInteger,
			value:   int32(0x0987),
			offset:  4,
		},
		// Test 3
		{
			bytes: Bytes{
				offset: 0,
				bytes:  []byte{0x02, 0x03, 0x09, 0x87, 0x65},
			},
			class:   classUniversal,
			tag:     tagInteger,
			typeTag: tagInteger,
			value:   int32(0x098765),
			offset:  5,
		},
		// Test 4
		{
			bytes: Bytes{
				offset: 0,
				bytes:  []byte{0x02, 0x04, 0x09, 0x87, 0x65, 0x43},
			},
			class:   classUniversal,
			tag:     tagInteger,
			typeTag: tagInteger,
			value:   int32(0x09876543),
			offset:  6,
		},
		// Test 5
		{
			bytes: Bytes{
				offset: 2,
				bytes:  []byte{0x30, 0x03, 0x02, 0x01, 0x0f},
			},
			class:   classUniversal,
			tag:     tagInteger,
			typeTag: tagInteger,
			value:   int32(0x0f),
			offset:  5,
		},
		// Test 6
		{
			bytes: Bytes{
				offset: 2,
				bytes:  []byte{0x30, 0x16, 0x02, 0x01, 0x0f, 0x60, 0x11, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x0a, 0x04, 0x08, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35},
			},
			class:   classUniversal,
			tag:     tagInteger,
			typeTag: tagInteger,
			value:   int32(0x0f),
			offset:  5,
		},
		// Test 7
		{
			bytes: Bytes{
				offset: 2,
				bytes:  []byte{0x30, 0x19, 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff, 0x60, 0x11, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x0a, 0x04, 0x08, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35},
			},
			class:   classUniversal,
			tag:     tagInteger,
			typeTag: tagInteger,
			value:   int32(0x07fffffff),
			offset:  8,
		},
		// Test 8
		{
			bytes: Bytes{
				offset: 0,
				bytes:  []byte{0x04, 0x08, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35},
			},
			class:   classUniversal,
			tag:     tagOctetString,
			typeTag: tagOctetString,
			value:   []byte("CRAM-MD5"),
			offset:  10,
		},
		// Test 9
		{
			bytes: Bytes{
				offset: 0,
				bytes:  []byte{0x04, 0x0d, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c},
			},
			class:   classUniversal,
			tag:     tagOctetString,
			typeTag: tagOctetString,
			value:   []byte("Hello, 世界"),
			offset:  15,
		},
		// Test 10
		{
			bytes: Bytes{
				offset: 10,
				bytes:  []byte{0x30, 0x1d, 0x02, 0x01, 0x05, 0x60, 0x18, 0x02, 0x01, 0x03, 0x04, 0x07, 0x6d, 0x79, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x80, 0x0a, 0x6d, 0x79, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64},
			},
			class:   classUniversal,
			tag:     tagOctetString,
			typeTag: tagOctetString,
			value:   []byte("myLogin"),
			offset:  19,
		},
	}
}
