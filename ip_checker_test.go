package traefik_cloudflare_plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIPChecker(t *testing.T) {

	assert := require.New(t)

	t.Run("Cloudflare API returns error", func(t *testing.T) {
		// fake server to mock Cloudflare API 500 response
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()

		ctx := context.Background()
		checker := NewCloudflareIPChecker(
			// The base URL must point to the mock server's address
			withBaseURL(mockServer.URL+"/client/v4/ips"),
			withRefreshInterval(5*time.Minute),
		)
		err := checker.Refresh(ctx)

		assert.ErrorContains(err, "Cloudflare API returned non-2xx status code: 500")
		assert.Len(checker.cidrs, 22)
	})
	t.Run("Cloudflare API returns invalid response", func(t *testing.T) {
		// fake server to mock Cloudflare API 500 response
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`invalid json`))
		}))
		defer mockServer.Close()

		ctx := context.Background()
		checker := NewCloudflareIPChecker(
			// The base URL must point to the mock server's address
			withBaseURL(mockServer.URL+"/client/v4/ips"),
			withRefreshInterval(5*time.Minute),
		)
		err := checker.Refresh(ctx)

		assert.ErrorContains(err, "invalid character 'i' looking for beginning of value")
		assert.Len(checker.cidrs, 22)
	})
	t.Run("Cloudflare invalid url", func(t *testing.T) {

		ctx := context.Background()
		checker := NewCloudflareIPChecker(
			// The base URL must point to the mock server's address
			withBaseURL("udp::example/client/v4/ips"),
			withRefreshInterval(5*time.Minute),
		)
		err := checker.Refresh(ctx)

		assert.ErrorContains(err, "unsupported protocol scheme")
		assert.Len(checker.cidrs, 22)
	})
}
