package badbotblocker

import (
	"net"
	"sync"
	"testing"
)

func TestIsBadIP(t *testing.T) {
	m := &BadBotMatcher{
		data: &badBotData{
			BadIPs: map[string]bool{
				"1.1.1.1": true,
			},
			BadSubnets: []net.IPNet{
				{
					IP:   net.ParseIP("2.2.2.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			mutex: sync.RWMutex{},
		},
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"1.1.1.1:1234", true},
		{"2.2.2.2:1234", true},
		{"3.3.3.3:1234", false},
	}

	for _, test := range tests {
		if m.isBadIP(test.ip) != test.expected {
			t.Errorf("isBadIP(%s) = %v; want %v", test.ip, !test.expected, test.expected)
		}
	}
}

func TestIsBadUserAgent(t *testing.T) {
	m := &BadBotMatcher{
		data: &badBotData{
			BadUserAgents: map[string]bool{
				"bad-bot": true,
			},
			mutex: sync.RWMutex{},
		},
	}

	tests := []struct {
		ua       string
		expected bool
	}{
		{"bad-bot", true},
		{"good-bot", false},
	}

	for _, test := range tests {
		if m.isBadUserAgent(test.ua) != test.expected {
			t.Errorf("isBadUserAgent(%s) = %v; want %v", test.ua, !test.expected, test.expected)
		}
	}
}

func TestIsBadReferer(t *testing.T) {
	m := &BadBotMatcher{
		data: &badBotData{
			BadReferers: map[string]bool{
				"bad-referer.com": true,
			},
			mutex: sync.RWMutex{},
		},
	}

	tests := []struct {
		referer  string
		expected bool
	}{
		{"bad-referer.com", true},
		{"good-referer.com", false},
	}

	for _, test := range tests {
		if m.isBadReferer(test.referer) != test.expected {
			t.Errorf("isBadReferer(%s) = %v; want %v", test.referer, !test.expected, test.expected)
		}
	}
}
