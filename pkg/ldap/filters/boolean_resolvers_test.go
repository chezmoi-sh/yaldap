package filters_test

import (
	"fmt"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	. "github.com/moznion/go-optional"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

const (
	filterAlwaysTrue ber.Tag = 0xffff - (iota + 1)
	filterAlwaysFalse
	filterAlwaysError
)

var (
	filterAlwaysTruePacket  = &ber.Packet{Identifier: ber.Identifier{Tag: filterAlwaysTrue}}
	filterAlwaysFalsePacket = &ber.Packet{Identifier: ber.Identifier{Tag: filterAlwaysFalse}}
	filterAlwaysErrorPacket = &ber.Packet{Identifier: ber.Identifier{Tag: filterAlwaysError}}
)

func init() {
	filters.AddFilterResolvers(filterAlwaysTrue, func(yaldaplib.Object, *ber.Packet) (bool, error) { return true, nil })
	filters.AddFilterResolvers(filterAlwaysFalse, func(yaldaplib.Object, *ber.Packet) (bool, error) { return false, nil })
	filters.AddFilterResolvers(filterAlwaysError, func(yaldaplib.Object, *ber.Packet) (bool, error) { return false, fmt.Errorf("`AlwaysError` filter") })
}

func TestAndResolver(t *testing.T) {
	tests := []filterResolverTestCase{
		{name: "OneSucceed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysTruePacket, filterAlwaysFalsePacket}},
			result: Some(false)},
		{name: "AllSucceed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysTruePacket, filterAlwaysTruePacket}},
			result: Some(true)},
		{name: "AllFailed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysFalsePacket, filterAlwaysFalsePacket}},
			result: Some(false)},

		{name: "NoSubfilter",
			filter: &ber.Packet{},
			result: Some(false)},
		{name: "OneErrored",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysErrorPacket}},
			result: None[bool]()},
		{name: "TrueBeforeErrored",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysTruePacket, filterAlwaysErrorPacket}},
			result: None[bool]()},
		{name: "FalseBeforeErrored",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysFalsePacket, filterAlwaysErrorPacket}},
			result: Some(false)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Run(t, nil, filters.AndResolver)
		})
	}
}

func TestOrResolver(t *testing.T) {
	tests := []filterResolverTestCase{
		{name: "OneSucceed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysTruePacket, filterAlwaysFalsePacket}},
			result: Some(true)},
		{name: "AllSucceed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysTruePacket, filterAlwaysTruePacket}},
			result: Some(true)},
		{name: "AllFailed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysFalsePacket, filterAlwaysFalsePacket}},
			result: Some(false)},

		{name: "NoSubfilter",
			filter: &ber.Packet{},
			result: Some(false)},
		{name: "OneErrored",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysErrorPacket}},
			result: None[bool]()},
		{name: "TrueBeforeErrored",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysTruePacket, filterAlwaysErrorPacket}},
			result: Some(true)},
		{name: "FalseBeforeErrored",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysFalsePacket, filterAlwaysErrorPacket}},
			result: None[bool]()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Run(t, nil, filters.OrResolver)
		})
	}
}

func TestNotResolver(t *testing.T) {
	tests := []filterResolverTestCase{
		{name: "Succeed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysTruePacket}},
			result: Some(false)},
		{name: "Failed",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysFalsePacket}},
			result: Some(true)},

		{name: "Errored",
			filter: &ber.Packet{Children: []*ber.Packet{filterAlwaysErrorPacket}},
			result: None[bool]()},
		{name: "InvalidFilter",
			filter: &ber.Packet{},
			result: None[bool]()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Run(t, nil, filters.NotResolver)
		})
	}
}
