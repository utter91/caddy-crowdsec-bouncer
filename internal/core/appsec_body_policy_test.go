package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type unreadBody struct{ reads int }

func (b *unreadBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("stream must not be read")
}
func (b *unreadBody) Close() error { return nil }

func appsecBodyContext(t *testing.T) context.Context {
	ctx := newCaddyVarsContext(t.Context())
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, "192.0.2.10")
	ctx, _ = httputils.EnsureIP(ctx)
	return ctx
}

func TestAppSecUnknownLengthFailClosed(t *testing.T) {
	for _, proto := range []int{2, 3} {
		for _, failOpen := range []bool{false, true} {
			body := &unreadBody{}
			r := httptest.NewRequest(http.MethodPost, "/upload", body)
			r.ProtoMajor = proto
			r.ContentLength = -1
			a := newAppSec("http://127.0.0.1:1", "dummy", 0, time.Second, failOpen, zaptest.NewLogger(t), &metrics.Provider{})
			err := a.checkRequest(appsecBodyContext(t), r)
			var decision *AppSecError
			require.ErrorAs(t, err, &decision)
			require.Equal(t, http.StatusLengthRequired, decision.StatusCode)
			require.Equal(t, "ban", decision.Action)
			require.Equal(t, 1, body.reads, "only a bounded one-byte probe is permitted")
			require.Same(t, body, r.Body)
		}
	}
}

func TestAppSecBodyPolicyCompatibility(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch} {
			payload := []byte("ordinary request")
			if method == http.MethodGet {
				payload = nil
			}
			r := httptest.NewRequest(method, "/path", bytes.NewReader(payload))
			r.ProtoMajor = proto
			if method == http.MethodGet {
				r.Body = http.NoBody
				r.ContentLength = -1
			}
			called := false
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, check *http.Request) {
				called = true
				b, err := io.ReadAll(check.Body)
				require.NoError(t, err)
				require.Equal(t, payload, bytes.TrimSpace(b))
				require.Equal(t, method, check.Header.Get("X-Crowdsec-Appsec-Verb"))
				require.Equal(t, int64(len(payload)), check.ContentLength)
				w.WriteHeader(http.StatusOK)
			}))
			a := newAppSec(s.URL, "dummy", 0, time.Second, false, zaptest.NewLogger(t), &metrics.Provider{})
			require.NoError(t, a.checkRequest(appsecBodyContext(t), r))
			require.True(t, called)
			b, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.Equal(t, payload, bytes.TrimSpace(b))
			s.Close()
		}
	}
}

func TestAppSecEmptyUnknownBody(t *testing.T) {
	for _, proto := range []int{2, 3} {
		r := httptest.NewRequest(http.MethodGet, "/empty", io.NopCloser(bytes.NewReader(nil)))
		r.ProtoMajor = proto
		r.ContentLength = -1
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
		a := newAppSec(s.URL, "dummy", 0, time.Second, false, zaptest.NewLogger(t), &metrics.Provider{})
		require.NoError(t, a.checkRequest(appsecBodyContext(t), r))
		s.Close()
	}
}
func TestAppSecUnknownStreamTimeout(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	started := time.Now()
	require.False(t, emptyUnknownLengthBody(t.Context(), r, 20*time.Millisecond))
	require.Less(t, time.Since(started), time.Second)
}
func TestAppSecUnknownProbeContextCanceled(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.False(t, emptyUnknownLengthBody(ctx, r, time.Second))
}
