// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package consul

import (
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"

	"github.com/greenpau/caddy-security/internal/consultest"
)

func TestConsulTicketParser(t *testing.T) {
	good := "tickets {\nrealm application\npublic_origin https://auth.example.test\nissuer_url https://issuer.example.test/signin\n}"
	if err := new(ConsulTicketIdentityProvider).UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"tickets", "tickets {\nrealm application\npublic_origin http://auth.example.test\nissuer_url https://issuer.example.test/signin\n}", "tickets {\nrealm application\npublic_origin https://auth.example.test\nissuer_url https://issuer.example.test/signin\ncapacity 0\n}"} {
		if new(ConsulTicketIdentityProvider).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)) == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
}
func TestConsulTicketProvider(t *testing.T) {
	address := consultest.Start(t)
	binding := consultest.Binding(t, address, "ticket-tests")
	open := func() *Provider {
		m := &ConsulTicketIdentityProvider{Name: "tickets", Realm: "application", PublicOrigin: "https://auth.example.test", IssuerURL: "https://issuer.example.test/signin", Capacity: 2, binding: binding}
		if _, err := m.IdentityProviderConfig(); err != nil {
			t.Fatal(err)
		}
		runtime, err := m.NewIdentityProvider(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		p := runtime.(*Provider)
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	a, b := open(), open()
	request := func(query string, cookie *http.Cookie) *http.Request {
		u, _ := url.Parse(a.CallbackURL() + query)
		r := &http.Request{Method: "GET", URL: u, Host: u.Host, TLS: &tls.ConnectionState{}}
		if cookie != nil {
			r.Header = http.Header{}
			r.AddCookie(cookie)
		}
		return r
	}
	begin, err := a.Login(t.Context(), request("", nil))
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := url.Parse(begin.RedirectURL)
	state := issuer.Query().Get("request")
	credential, err := b.Issue(t.Context(), state, &idp.LoginIdentity{Subject: "subject-one", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
	if err != nil {
		t.Fatal(err)
	}
	query := "?" + (url.Values{"state": {state}, "ticket": {credential}}).Encode()
	if _, err := b.Login(t.Context(), request(query, nil)); !errors.Is(err, ErrDenied) {
		t.Fatal("unbound browser accepted", err)
	}
	var wg sync.WaitGroup
	wins := make(chan bool, 2)
	for _, p := range []*Provider{a, b} {
		wg.Add(1)
		go func(p *Provider) {
			defer wg.Done()
			result, err := p.Login(t.Context(), request(query, begin.Cookie))
			if err == nil && (result.Identity.Subject != "subject-one" || result.ExternalIdentity.Evidence.UserID == "") {
				t.Error("missing trusted identity")
			}
			wins <- err == nil
		}(p)
	}
	wg.Wait()
	close(wins)
	count := 0
	for ok := range wins {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent ticket winners: %d", count)
	}
	if _, err := a.Issue(t.Context(), state, &idp.LoginIdentity{Subject: "another", Roles: []string{"authp/user"}}); err == nil {
		t.Fatal("spent state reissued")
	}
	var pending []string
	for range 2 {
		result, err := b.Login(t.Context(), request("", nil))
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(result.RedirectURL)
		pending = append(pending, u.Query().Get("request"))
	}
	if _, err := b.Login(t.Context(), request("", nil)); err == nil {
		t.Fatal("ticket capacity not enforced")
	}
	if err := b.run(t.Context(), func(d *document) (bool, error) {
		for id, v := range d.Tickets {
			v.Expires = 1
			d.Tickets[id] = v
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Issue(t.Context(), pending[0], &idp.LoginIdentity{Subject: "expired", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}}); !errors.Is(err, ErrDenied) {
		t.Fatal("expired request issued", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Login(t.Context(), request("", nil)); err != nil {
		t.Fatal("peer close lost shared client", err)
	}
}

func TestConsulTicketClaimRetriesFailedAttachment(t *testing.T) {
	address := consultest.Start(t)
	binding := consultest.Binding(t, address, "ticket-attachment-recovery")
	open := func(unbound bool) *Provider {
		m := &ConsulTicketIdentityProvider{
			Name:         "tickets",
			Realm:        "application",
			PublicOrigin: "https://auth.example.test",
			IssuerURL:    "https://issuer.example.test/signin",
			Capacity:     4,
			binding:      binding,
		}
		if unbound {
			m.Attachment = &attachment.Config{LocalIdentityStore: "accounts"}
		}
		if _, err := m.IdentityProviderConfig(); err != nil {
			t.Fatal(err)
		}
		runtime, err := m.NewIdentityProvider(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		p := runtime.(*Provider)
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	winner := open(true)
	peer, retry := open(false), open(false)
	request := func(query string, cookie *http.Cookie) *http.Request {
		u, _ := url.Parse(winner.CallbackURL() + query)
		r := &http.Request{Method: http.MethodGet, URL: u, Host: u.Host, TLS: &tls.ConnectionState{}}
		if cookie != nil {
			r.Header = http.Header{}
			r.AddCookie(cookie)
		}
		return r
	}
	begin, err := winner.Login(t.Context(), request("", nil))
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := url.Parse(begin.RedirectURL)
	state := issuer.Query().Get("request")
	credential, err := peer.Issue(t.Context(), state, &idp.LoginIdentity{Subject: "subject-recover", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
	if err != nil {
		t.Fatal(err)
	}
	query := "?" + (url.Values{"state": {state}, "ticket": {credential}}).Encode()
	// The explicit attachment is intentionally unbound, so its first attempt
	// fails after the winning browser has claimed the one-time ticket.
	if result, err := winner.Login(t.Context(), request(query, begin.Cookie)); err == nil || result != nil {
		t.Fatal("failed attachment published a successful login result")
	}
	digest := sha256.Sum256([]byte(state))
	if err := winner.run(t.Context(), func(d *document) (bool, error) {
		claimed, ok := d.Tickets[digest]
		if !ok || !claimed.Consumed || !claimed.AttachmentFailed || claimed.Identity == nil || claimed.Identity.Subject != "subject-recover" {
			t.Fatal("failed attachment did not retain the browser-owned retryable claim")
		}
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	otherBrowser, err := secret()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := winner.Login(t.Context(), request(query, &http.Cookie{Name: winner.config.CookieName, Value: otherBrowser})); !errors.Is(err, ErrDenied) || result != nil {
		t.Fatal("another browser recovered the claimed ticket", err)
	}
	// Concurrent same-browser retries reclaim the failed claim atomically, so
	// exactly one of them may publish the recovered authentication result.
	type outcome struct {
		result *idp.HTTPLoginResult
		err    error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, p := range []*Provider{peer, retry} {
		wg.Add(1)
		go func(p *Provider) {
			defer wg.Done()
			result, err := p.Login(t.Context(), request(query, begin.Cookie))
			results <- outcome{result: result, err: err}
		}(p)
	}
	wg.Wait()
	close(results)
	var recovered *idp.HTTPLoginResult
	winners, userIDs := 0, map[string]bool{}
	for got := range results {
		if got.err != nil {
			continue
		}
		if got.result == nil || got.result.Identity == nil || got.result.Identity.Subject != "subject-recover" || got.result.ExternalIdentity.Evidence.UserID == "" || got.result.Cookie == nil || got.result.Cookie.MaxAge != -1 {
			t.Fatal("recovered ticket published an incomplete result")
		}
		winners++
		userIDs[got.result.ExternalIdentity.Evidence.UserID] = true
		recovered = got.result
	}
	if winners != 1 || len(userIDs) != 1 || recovered == nil {
		t.Fatalf("recovered ticket produced %d successful results with %d identities", winners, len(userIDs))
	}
	// Once the attachment result is committed, the ticket is spent. Concurrent
	// or later callbacks cannot publish a second success page.
	if replay, err := winner.Login(t.Context(), request(query, begin.Cookie)); !errors.Is(err, ErrDenied) || replay != nil {
		t.Fatal("completed ticket accepted a second successful callback", err)
	}
	// A retryable attachment failure still belongs to the consumed ticket, so
	// the trusted application cannot issue that state again.
	if _, err := peer.Issue(t.Context(), state, &idp.LoginIdentity{Subject: "another", Roles: []string{"authp/user"}}); !errors.Is(err, ErrDenied) {
		t.Fatal("retryable consumed state accepted reissue", err)
	}
}
