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
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var poolKey = caddy.NewUsagePool()

type badBotData struct {
	BadUserAgents map[string]bool
	BadIPs        map[string]bool
	BadReferers   map[string]bool

	mutex sync.RWMutex
}

func (b *badBotData) Destruct() error {
	return nil
}

func init() {
	caddy.RegisterModule(BadBotBlocker{})
	httpcaddyfile.RegisterHandlerDirective("badbotblocker", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("badbotblocker", httpcaddyfile.Before, "header")
}

// BadBotBlocker implements an HTTP handler that writes the
// visitor's IP address to a file or stream.
type BadBotBlocker struct {
	ExcludeUserAgents []string `json:"exclude_user_agents,omitempty"`
	ExcludeIPs        []string `json:"exclude_ips,omitempty"`

	data *badBotData

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (BadBotBlocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.badbotblocker",
		New: func() caddy.Module { return new(BadBotBlocker) },
	}
}

// Provision implements caddy.Provisioner.
func (b *BadBotBlocker) Provision(ctx caddy.Context) error {
	b.logger = ctx.Logger(b)

	resource, _, err := poolKey.LoadOrNew("badbotblocker_lists", func() (caddy.Destructor, error) {
		data := &badBotData{
			BadUserAgents: make(map[string]bool),
			BadIPs:        make(map[string]bool),
			BadReferers:   make(map[string]bool),
		}

		err := updateLists(data)
		if err != nil {
			return nil, err
		}

		b.logger.Info(
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

	b.data = resource.(*badBotData)

	return nil
}

// Validate implements caddy.Validator.
func (b *BadBotBlocker) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (b BadBotBlocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	userAgent := r.UserAgent()
	referer := r.Referer()

	b.logger.Info(
		"New connection",
		zap.String("ip", ip),
		zap.String("useragent", userAgent),
		zap.String("referer", referer),
	)

	reportBadRequest := func() error {
		return caddyhttp.StaticResponse{Abort: true}.ServeHTTP(w, r, next)
	}

	if b.isBadUserAgent(userAgent) {
		return reportBadRequest()
	}
	if b.isBadReferer(referer) {
		return reportBadRequest()
	}
	if b.isBadIP(ip) {
		return reportBadRequest()
	}

	return next.ServeHTTP(w, r)
}

// Funzioni di aiuto per controllare liste malevoli
func (b *BadBotBlocker) isBadIP(ip string) bool {
	host, _, _ := net.SplitHostPort(ip)

	b.data.mutex.RLock()
	defer b.data.mutex.RUnlock()

	return b.data.BadIPs[host]
}

func (b *BadBotBlocker) isBadUserAgent(userAgent string) bool {

	b.data.mutex.RLock()
	defer b.data.mutex.RUnlock()

	return b.data.BadUserAgents[userAgent]
}

func (b *BadBotBlocker) isBadReferer(referer string) bool {
	b.data.mutex.RLock()
	defer b.data.mutex.RUnlock()

	return b.data.BadReferers[referer]
}

// Funzione per aggiornare le liste
func updateLists(data *badBotData) error {
	data.mutex.Lock()
	defer data.mutex.Unlock()

	// Scarica la lista di User-Agent malevoli
	userAgentList, err := fetchList(
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list",
	)
	if err != nil {
		return err
	}
	data.BadUserAgents = make(map[string]bool)
	for _, ua := range userAgentList {
		data.BadUserAgents[ua] = true
	}

	subnets := make([]net.IPNet, 0)

	bingIpRangeList, err := fetchList(
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bing-ip-ranges.list",
	)
	if err != nil {
		return err
	}
	for _, ip := range bingIpRangeList {
		if _, subnet, err := net.ParseCIDR(ip); err == nil {
			subnets = append(subnets, *subnet)
		}
	}
	cloudflareIpRangeList, err := fetchList(
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/cloudflare-ip-ranges.list",
	)
	if err != nil {
		return err
	}
	for _, ip := range cloudflareIpRangeList {
		if _, subnet, err := net.ParseCIDR(ip); err == nil {
			subnets = append(subnets, *subnet)
		}
	}
	googleIpRangeList, err := fetchList(
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/google-ip-ranges.list",
	)
	if err != nil {
		return err
	}
	for _, ip := range googleIpRangeList {
		if _, subnet, err := net.ParseCIDR(ip); err == nil {
			subnets = append(subnets, *subnet)
		}
	}

	// Scarica la lista di IP malevoli
	ipList, err := fetchList(
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-ip-addresses.list",
	)
	if err != nil {
		return err
	}
	data.BadIPs = make(map[string]bool)
	for _, ipStr := range ipList {
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

	// Scarica la lista di Referer malevoli
	refererList, err := fetchList(
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-referrers.list",
	)
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
func fetchList(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var list []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 && !strings.HasPrefix(line, "#") { // Ignora i commenti
			list = append(list, line)
		}
	}
	return list, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (b *BadBotBlocker) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var b BadBotBlocker
	err := b.UnmarshalCaddyfile(h.Dispenser)
	return b, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*BadBotBlocker)(nil)
	_ caddy.Validator             = (*BadBotBlocker)(nil)
	_ caddyhttp.MiddlewareHandler = (*BadBotBlocker)(nil)
	_ caddyfile.Unmarshaler       = (*BadBotBlocker)(nil)
)
