package badbotblocker

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var poolKey = caddy.NewUsagePool()

type badBotData struct {
	BadUserAgents map[string]bool
	BadIPs        map[string]bool
	BadReferers   map[string]bool
	BadSubnets    []net.IPNet

	mutex sync.RWMutex
}

func (b *badBotData) Destruct() error {
	return nil
}

func init() {
	caddy.RegisterModule(BadBotMatcher{})
}

// BadBotMatcher implements an HTTP request matcher.
type BadBotMatcher struct {
	ExcludeUserAgents []string `json:"exclude_user_agents,omitempty"`
	ExcludeIPs        []string `json:"exclude_ips,omitempty"`

	UserAgentListURL []string `json:"user_agent_list_url,omitempty"`
	IPListURL        []string `json:"ip_list_url,omitempty"`
	RefererListURL   []string `json:"referer_list_url,omitempty"`
	TrustedIPListURL []string `json:"trusted_ip_list_url,omitempty"`

	data *badBotData

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (BadBotMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.badbotblocker",
		New: func() caddy.Module { return new(BadBotMatcher) },
	}
}

// Provision implements caddy.Provisioner.
func (m *BadBotMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	resource, _, err := poolKey.LoadOrNew("badbotblocker_lists", func() (caddy.Destructor, error) {
		data := &badBotData{
			BadUserAgents: make(map[string]bool),
			BadIPs:        make(map[string]bool),
			BadReferers:   make(map[string]bool),
			BadSubnets:    make([]net.IPNet, 0),
		}

		err := m.updateLists(data)
		if err != nil {
			return nil, err
		}

		m.logger.Info(
			"Block list downloaded succefully",
			zap.Int("ip_loaded", len(data.BadIPs)),
			zap.Int("ua_loaded", len(data.BadUserAgents)),
			zap.Int("referer_loaded", len(data.BadReferers)),
		)

		return data, nil
	})

	if err != nil {
		return err
	}

	m.data = resource.(*badBotData)

	return nil
}

// Validate implements caddy.Validator.
func (m *BadBotMatcher) Validate() error {
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *BadBotMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for d.NextBlock(0) {
		switch d.Val() {
		case "exclude_user_agents":
			m.ExcludeUserAgents = d.RemainingArgs()
		case "exclude_ips":
			m.ExcludeIPs = d.RemainingArgs()
		case "user_agent_list_url":
			m.UserAgentListURL = d.RemainingArgs()
		case "ip_list_url":
			m.IPListURL = d.RemainingArgs()
		case "referer_list_url":
			m.RefererListURL = d.RemainingArgs()
		case "trusted_ip_list_url":
			m.TrustedIPListURL = d.RemainingArgs()
		}
	}

	return nil
}

// Match returns true if the request is from a bad bot.
func (m BadBotMatcher) Match(r *http.Request) bool {
	match, err := m.MatchWithError(r)
	if err != nil {
		m.logger.Error("matching request", zap.Error(err))
		return false
	}
	return match
}

// MatchWithError returns true if the request is from a bad bot.
func (m BadBotMatcher) MatchWithError(r *http.Request) (bool, error) {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	userAgent := r.UserAgent()
	referer := r.Referer()

	if m.isBadUserAgent(userAgent) {
		m.logger.Info(
			"Blocked request",
			zap.String("reason", "Bad User-Agent"),
			zap.String("ip", ip),
			zap.String("useragent", userAgent),
			zap.String("referer", referer),
		)
		return true, nil
	}
	if m.isBadReferer(referer) {
		m.logger.Info(
			"Blocked request",
			zap.String("reason", "Bad Referer"),
			zap.String("ip", ip),
			zap.String("useragent", userAgent),
			zap.String("referer", referer),
		)
		return true, nil
	}
	if m.isBadIP(ip) {
		m.logger.Info(
			"Blocked request",
			zap.String("reason", "Bad IP"),
			zap.String("ip", ip),
			zap.String("useragent", userAgent),
			zap.String("referer", referer),
		)
		return true, nil
	}

	return false, nil
}

// Funzioni di aiuto per controllare liste malevoli
func (m *BadBotMatcher) isBadIP(ip string) bool {
	host, _, _ := net.SplitHostPort(ip)
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	m.data.mutex.RLock()
	defer m.data.mutex.RUnlock()

	if m.data.BadIPs[host] {
		return true
	}

	for _, subnet := range m.data.BadSubnets {
		if subnet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (m *BadBotMatcher) isBadUserAgent(userAgent string) bool {
	m.data.mutex.RLock()
	defer m.data.mutex.RUnlock()

	return m.data.BadUserAgents[userAgent]
}

func (m *BadBotMatcher) isBadReferer(referer string) bool {
	m.data.mutex.RLock()
	defer m.data.mutex.RUnlock()

	return m.data.BadReferers[referer]
}

// Funzione per aggiornare le liste
func (m *BadBotMatcher) updateLists(data *badBotData) error {
	data.mutex.Lock()
	defer data.mutex.Unlock()

	// Scarica la lista di User-Agent malevoli
	userAgentList, err := m.fetchList(m.UserAgentListURL, []string{
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list",
	})
	if err != nil {
		return err
	}
	data.BadUserAgents = make(map[string]bool)
	for _, ua := range userAgentList {
		data.BadUserAgents[ua] = true
	}

	subnets := make([]net.IPNet, 0)

	trustedIpRangeList, err := m.fetchList(m.TrustedIPListURL, []string{
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bing-ip-ranges.list",
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/cloudflare-ip-ranges.list",
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/google-ip-ranges.list",
	})
	if err != nil {
		return err
	}
	for _, ip := range trustedIpRangeList {
		if _, subnet, err := net.ParseCIDR(ip); err == nil {
			subnets = append(subnets, *subnet)
		}
	}

	// Scarica la lista di IP malevoli
	ipList, err := m.fetchList(m.IPListURL, []string{
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-ip-addresses.list",
	})
	if err != nil {
		return err
	}
	data.BadIPs = make(map[string]bool)
	for _, ipStr := range ipList {
		if strings.Contains(ipStr, "/") {
			_, subnet, err := net.ParseCIDR(ipStr)
			if err == nil {
				data.BadSubnets = append(data.BadSubnets, *subnet)
			}
		} else {
			isBad := true
			for _, subnet := range subnets {
				ip := net.ParseIP(ipStr)
				if subnet.Contains(ip) {
					isBad = false
					break
				}
			}
			data.BadIPs[ipStr] = isBad
		}
	}

	// Scarica la lista di Referer malevoli
	refererList, err := m.fetchList(m.RefererListURL, []string{
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-referrers.list",
	})
	if err != nil {
		return err
	}
	data.BadReferers = make(map[string]bool)
	for _, referer := range refererList {
		data.BadReferers[referer] = true
	}

	return nil
}

// Funzione di aiuto per scaricare le liste
func (m *BadBotMatcher) fetchList(urls []string, defaultUrls []string) ([]string, error) {
	if len(urls) == 0 {
		urls = defaultUrls
	}

	var list []string
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if len(line) > 0 && !strings.HasPrefix(line, "#") { // Ignora i commenti
				list = append(list, line)
			}
		}
	}

	return list, nil
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*BadBotMatcher)(nil)
	_ caddy.Validator                   = (*BadBotMatcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*BadBotMatcher)(nil)
	_ caddyfile.Unmarshaler             = (*BadBotMatcher)(nil)
)
