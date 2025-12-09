package traefik_cloudflare_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Vandebron/traefik-cloudflare-plugin/internal"
)

var (
	// Fallback Cloudflare IPv4 ranges in case the API is unreachable.
	// https://api.cloudflare.com/client/v4/ips
	fallbackIPV4 = []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}
	// Fallback Cloudflare IPv6 ranges in case the API is unreachable.
	// https://api.cloudflare.com/client/v4/ips
	fallbackIPV6 = []string{
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}
)

type cloudflareIPChecker struct {
	refreshInterval   time.Duration
	cloudflareBaseURL string

	client *http.Client

	cidrs       []*net.IPNet
	lastRefresh time.Time
}

type option func(*cloudflareIPChecker)

// withRefreshInterval sets the refresh interval for the Cloudflare IP checker.
func withRefreshInterval(t time.Duration) option {
	return func(c *cloudflareIPChecker) {
		c.refreshInterval = t
	}
}

// withBaseURL sets the Cloudflare API base URL for the Cloudflare IP checker.
func withBaseURL(url string) option {
	return func(c *cloudflareIPChecker) {
		c.cloudflareBaseURL = url
	}
}

// NewCloudflareIPChecker creates a new Cloudflare IP checker with the given options.
func NewCloudflareIPChecker(opts ...option) *cloudflareIPChecker {
	// We should always fallback to the hard coded IPs
	fallbackCIDRs := &cloudflareResponse{
		Success: true,
		Result: &cloudflareIPs{
			IPv4CIDRs: fallbackIPV4,
			IPv6CIDRs: fallbackIPV6,
		},
	}
	// set sensible defaults
	c := &cloudflareIPChecker{
		refreshInterval:   24 * time.Hour,
		cloudflareBaseURL: "https://api.cloudflare.com/client/v4/ips",
		client:            http.DefaultClient,
		cidrs:             fallbackCIDRs.Data(),
	}

	// overwrite defaults with options
	for _, opt := range opts {
		opt(c)
	}

	return c
}

type ipChecker interface {
	CheckIP(context.Context, net.IP) (bool, error)
}

type staticIPChecker struct {
	Cidrs []*net.IPNet
}

type cloudflareResponse struct {
	Success bool               `json:"success"`
	Errors  []*cloudflareError `json:"errors"`
	Result  *cloudflareIPs     `json:"result"`
}

type cloudflareIPs struct {
	IPv4CIDRs []string `json:"ipv4_cidrs"`
	IPv6CIDRs []string `json:"ipv6_cidrs"`
}

type cloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *staticIPChecker) CheckIP(ctx context.Context, ip net.IP) (bool, error) {
	for _, cidr := range c.Cidrs {
		if cidr.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

// CheckIP checks if the given IP is within the Cloudflare IP ranges.
func (c *cloudflareIPChecker) CheckIP(ctx context.Context, ip net.IP) (bool, error) {
	if c.refreshInterval > 0 && internal.Now().Sub(c.lastRefresh) > c.refreshInterval {
		err := c.Refresh(ctx)
		if err != nil {
			if len(c.cidrs) == 0 {
				return false, fmt.Errorf("error: failed to refresh Cloudflare IPs: %w", err)
			}
			slog.Error(fmt.Sprintf("warning: failed to refresh Cloudflare IPs: %s, keep current cidrs", err))
		}
	}

	for _, cidr := range c.cidrs {
		if cidr.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

// Refresh fetches the latest Cloudflare IP ranges from the
// Cloudflare API. If the API is unreachable, it falls back to
// predefined IP ranges.
func (c *cloudflareIPChecker) Refresh(ctx context.Context) error {

	req, err := http.NewRequestWithContext(ctx,
		http.MethodGet,
		c.cloudflareBaseURL,
		nil,
	)

	c.lastRefresh = internal.Now().Add(5*time.Minute - c.refreshInterval)

	if err != nil {
		return err
	}

	res, err := c.client.Do(req)
	if err != nil {
		slog.Error(fmt.Sprintf("warning: failed to reach Cloudflare API: %s, keep current cidrs", err))
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("Cloudflare API returned non-2xx status code: %d", res.StatusCode)
	}

	var resp cloudflareResponse

	err = json.NewDecoder(res.Body).Decode(&resp)
	if err != nil {
		return err
	}

	c.cidrs = resp.Data()
	c.lastRefresh = internal.Now()
	return nil
}

func (r *cloudflareResponse) Data() []*net.IPNet {
	if !r.Success || r.Result == nil {
		for _, e := range r.Errors {
			err := e.Error()
			if err != nil {
				return nil
			}
		}

		return nil
	}

	res := make([]*net.IPNet, 0, len(r.Result.IPv4CIDRs)+len(r.Result.IPv6CIDRs))

	for _, c := range r.Result.IPv4CIDRs {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return nil
		}

		res = append(res, cidr)
	}

	for _, c := range r.Result.IPv6CIDRs {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return nil
		}

		res = append(res, cidr)
	}

	return res
}

func (e *cloudflareError) Error() error {
	if e == nil {
		return nil
	}

	return fmt.Errorf("error %d: %s", e.Code, e.Message)
}
