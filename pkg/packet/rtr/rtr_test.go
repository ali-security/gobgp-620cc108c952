// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rtr

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func verifyRTRMessage(t *testing.T, m1 RTRMessage) {
	buf1, _ := m1.Serialize()
	m2, err := ParseRTR(buf1)
	require.NoError(t, err)

	buf2, err := m2.Serialize()
	require.NoError(t, err)

	assert.Equal(t, buf1, buf2, "buf1: %v buf2: %v", hex.EncodeToString(buf1), hex.EncodeToString(buf2))
}

func randUint32() uint32 {
	rand.Seed(time.Now().UnixNano())
	return rand.Uint32()
}

func Test_RTRSerialNotify(t *testing.T) {
	id := uint16(time.Now().Unix())
	sn := randUint32()
	verifyRTRMessage(t, NewRTRSerialNotify(id, sn))
}

func Test_RTRSerialQuery(t *testing.T) {
	id := uint16(time.Now().Unix())
	sn := randUint32()
	verifyRTRMessage(t, NewRTRSerialQuery(id, sn))
}

func Test_RTRResetQuery(t *testing.T) {
	verifyRTRMessage(t, NewRTRResetQuery())
}

func Test_RTRCacheResponse(t *testing.T) {
	id := uint16(time.Now().Unix())
	verifyRTRMessage(t, NewRTRCacheResponse(id))
}

type rtrIPPrefixTestCase struct {
	pString string
	pLen    uint8
	mLen    uint8
	asn     uint32
	flags   uint8
}

var rtrIPPrefixTestCases = []rtrIPPrefixTestCase{
	{"192.168.0.0", 16, 32, 65001, ANNOUNCEMENT},
	{"192.168.0.0", 16, 32, 65001, WITHDRAWAL},
	{"2001:db8::", 32, 128, 65001, ANNOUNCEMENT},
	{"2001:db8::", 32, 128, 65001, WITHDRAWAL},
	{"::ffff:0.0.0.0", 96, 128, 65001, ANNOUNCEMENT},
	{"::ffff:0.0.0.0", 96, 128, 65001, WITHDRAWAL},
}

func Test_RTRIPPrefix(t *testing.T) {
	for i := range rtrIPPrefixTestCases {
		test := &rtrIPPrefixTestCases[i]
		addr := net.ParseIP(test.pString)
		verifyRTRMessage(t, NewRTRIPPrefix(addr, test.pLen, test.mLen, test.asn, test.flags))
	}
}

func Test_RTREndOfData(t *testing.T) {
	id := uint16(time.Now().Unix())
	sn := randUint32()
	verifyRTRMessage(t, NewRTREndOfData(id, sn))
}

func Test_RTRCacheReset(t *testing.T) {
	verifyRTRMessage(t, NewRTRCacheReset())
}

func Test_RTRErrorReport(t *testing.T) {
	errPDU, _ := NewRTRResetQuery().Serialize()
	errText1 := []byte("Couldn't send CacheResponce PDU")
	errText2 := []byte("Wrong Length of PDU: 10 bytes")

	// See 5.10 ErrorReport in RFC6810
	// when it doesn't have both "erroneous PDU" and "Arbitrary Text"
	verifyRTRMessage(t, NewRTRErrorReport(NO_DATA_AVAILABLE, nil, nil))

	// when it has "erroneous PDU"
	verifyRTRMessage(t, NewRTRErrorReport(UNSUPPORTED_PROTOCOL_VERSION, errPDU, nil))

	// when it has "ArbitaryText"
	verifyRTRMessage(t, NewRTRErrorReport(INTERNAL_ERROR, nil, errText1))

	// when it has both "erroneous PDU" and "Arbitrary Text"
	verifyRTRMessage(t, NewRTRErrorReport(CORRUPT_DATA, errPDU, errText2))
}

// Test_ParseRTRShortMessage tests the CVE-2025-43973 fix.
// ParseRTR used to index the received buffer without checking that a whole
// common header is available, so a truncated PDU made it run off the end of
// the buffer instead of returning an error.
func Test_ParseRTRShortMessage(t *testing.T) {
	for length := 0; length < RTR_MIN_LEN; length++ {
		data := make([]byte, length)
		if length > 1 {
			// Use a known message type so that only the truncated
			// length can make ParseRTR fail.
			data[1] = RTR_RESET_QUERY
		}
		assert.NotPanics(t, func() {
			msg, err := ParseRTR(data)
			assert.Error(t, err, "ParseRTR should fail with %d bytes", length)
			assert.Nil(t, msg, "ParseRTR should return no message with %d bytes", length)
		}, "ParseRTR should not run off the end of a %d byte buffer", length)
	}

	// A complete PDU is still accepted.
	buf, err := NewRTRResetQuery().Serialize()
	require.NoError(t, err)
	require.Equal(t, RTR_MIN_LEN, len(buf))

	msg, err := ParseRTR(buf)
	require.NoError(t, err)
	assert.NotNil(t, msg)
}

// Test_SplitRTRLength tests the CVE-2025-43973 fix.
// SplitRTR must never hand a buffer shorter than the advertised length over
// to ParseRTR, whatever length the remote side advertises.
func Test_SplitRTRLength(t *testing.T) {
	buf, err := NewRTRSerialNotify(uint16(1), uint32(2)).Serialize()
	require.NoError(t, err)
	require.Equal(t, RTR_SERIAL_NOTIFY_LEN, len(buf))

	// Not even the common header has been received yet.
	advance, token, err := SplitRTR(buf[:RTR_MIN_LEN-1], false)
	assert.NoError(t, err)
	assert.Equal(t, 0, advance)
	assert.Nil(t, token)

	// The common header is complete but the PDU is not.
	advance, token, err = SplitRTR(buf[:len(buf)-1], false)
	assert.NoError(t, err)
	assert.Equal(t, 0, advance)
	assert.Nil(t, token)

	// A length below the common header length is rejected.
	broken := make([]byte, len(buf))
	copy(broken, buf)
	binary.BigEndian.PutUint32(broken[4:8], uint32(RTR_MIN_LEN-1))
	_, _, err = SplitRTR(broken, false)
	assert.Error(t, err)

	// The largest length the remote side can advertise must be compared
	// without wrapping around, on 32 bit platforms as well.
	binary.BigEndian.PutUint32(broken[4:8], ^uint32(0))
	assert.NotPanics(t, func() {
		advance, token, err := SplitRTR(broken, false)
		assert.NoError(t, err)
		assert.Equal(t, 0, advance)
		assert.Nil(t, token)
	}, "SplitRTR should not slice beyond the end of the buffer")

	// A complete PDU is returned as a whole.
	advance, token, err = SplitRTR(append(buf, buf...), false)
	assert.NoError(t, err)
	assert.Equal(t, len(buf), advance)
	assert.Equal(t, buf, token)

	msg, err := ParseRTR(token)
	require.NoError(t, err)
	assert.NotNil(t, msg)
}
