// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/coocood/freecache"
	"github.com/mohae/deepcopy"

	"github.com/ory/x/errorsx"

	"github.com/ory/x/randx"

	"github.com/ory/fosite"
	enigma "github.com/ory/fosite/token/hmac"
)

const POLLING_RATE_LIMITING_LEEWAY = 200 * time.Millisecond

// DeviceFlowSession is a fosite.Session container specific for the device flow.
type DeviceFlowSession interface {
	// GetBrowserFlowCompleted returns the flag indicating whether user has completed the browser flow or not.
	GetBrowserFlowCompleted() bool

	// SetBrowserFlowCompleted allows client to mark user has completed the browser flow.
	SetBrowserFlowCompleted(flag bool)

	fosite.Session
}

// DefaultDeviceFlowSession is a DeviceFlowSession implementation for the device flow.
type DefaultDeviceFlowSession struct {
	ExpiresAt            map[fosite.TokenType]time.Time `json:"expires_at"`
	Username             string                         `json:"username"`
	Subject              string                         `json:"subject"`
	Extra                map[string]interface{}         `json:"extra"`
	BrowserFlowCompleted bool                           `json:"browser_flow_completed"`
}

func (s *DefaultDeviceFlowSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

func (s *DefaultDeviceFlowSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}

	if _, ok := s.ExpiresAt[key]; !ok {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

func (s *DefaultDeviceFlowSession) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

func (s *DefaultDeviceFlowSession) SetSubject(subject string) {
	s.Subject = subject
}

func (s *DefaultDeviceFlowSession) GetSubject() string {
	if s == nil {
		return ""
	}

	return s.Subject
}

func (s *DefaultDeviceFlowSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(fosite.Session)
}

func (s *DefaultDeviceFlowSession) GetBrowserFlowCompleted() bool {
	if s == nil {
		return false
	}

	return s.BrowserFlowCompleted
}

func (s *DefaultDeviceFlowSession) SetBrowserFlowCompleted(flag bool) {
	s.BrowserFlowCompleted = flag
}

// DefaultDeviceStrategy implements the default device strategy
type DefaultDeviceStrategy struct {
	Enigma           *enigma.HMACStrategy
	RateLimiterCache *freecache.Cache
	Config           interface {
		fosite.DeviceProvider
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

var _ RFC8628CodeStrategy = (*DefaultDeviceStrategy)(nil)

// GenerateUserCode generates a user_code
func (h *DefaultDeviceStrategy) GenerateUserCode(ctx context.Context) (string, string, error) {
	seq, err := randx.RuneSequence(8, []rune(randx.AlphaUpper))
	if err != nil {
		return "", "", err
	}
	userCode := string(seq)
	signUserCode, signErr := h.UserCodeSignature(ctx, userCode)
	if signErr != nil {
		return "", "", err
	}
	return userCode, signUserCode, nil
}

// UserCodeSignature generates a user_code signature
func (h *DefaultDeviceStrategy) UserCodeSignature(ctx context.Context, token string) (string, error) {
	return h.Enigma.GenerateHMACForString(ctx, token)
}

// ValidateUserCode validates a user_code
func (h *DefaultDeviceStrategy) ValidateUserCode(ctx context.Context, r fosite.Requester, code string) error {
	exp := r.GetSession().GetExpiresAt(fosite.UserCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", exp))
	}
	return nil
}

// GenerateDeviceCode generates a device_code
func (h *DefaultDeviceStrategy) GenerateDeviceCode(ctx context.Context) (string, string, error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return "ory_dc_" + token, sig, nil
}

// DeviceCodeSignature generates a device_code signature
func (h *DefaultDeviceStrategy) DeviceCodeSignature(ctx context.Context, token string) (string, error) {
	return h.Enigma.Signature(token), nil
}

// ValidateDeviceCode validates a device_code
func (h *DefaultDeviceStrategy) ValidateDeviceCode(ctx context.Context, r fosite.Requester, code string) error {
	exp := r.GetSession().GetExpiresAt(fosite.DeviceCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, strings.TrimPrefix(code, "ory_dc_"))
}

// ShouldRateLimit is used to decide whether a request should be rate-limited
func (h *DefaultDeviceStrategy) ShouldRateLimit(context context.Context, code string) (bool, error) {
	key := code + "_limiter"

	keyBytes := []byte(key)
	object, err := h.RateLimiterCache.Get(keyBytes)
	// This code is not in the cache, so we just add it
	if err != nil {
		timer := new(expirationTimer)
		timer.Counter = 1
		timer.NotUntil = h.getNotUntil(context, 1)
		exp, err := h.serializeExpiration(timer)
		if err != nil {
			return false, errorsx.WithStack(fosite.ErrServerError.WithHintf("Failed to serialize expiration struct %s", err))
		}
		// Set the expiration time as value, and use the lifespan of the device code as TTL.
		h.RateLimiterCache.Set(keyBytes, exp, int(h.Config.GetDeviceAndUserCodeLifespan(context).Seconds()))
		return false, nil
	}

	expiration, err := h.deserializeExpiration(object)
	if err != nil {
		return false, errorsx.WithStack(fosite.ErrServerError.WithHintf("Failed to store to rate limit cache: %s", err))
	}

	// The code is valid and enough time has passed since the last call.
	if time.Now().After(expiration.NotUntil) {
		expiration.NotUntil = h.getNotUntil(context, expiration.Counter)
		exp, err := h.serializeExpiration(expiration)
		if err != nil {
			return false, errorsx.WithStack(fosite.ErrServerError.WithHintf("Failed to serialize expiration struct %s", err))
		}
		h.RateLimiterCache.Set(keyBytes, exp, int(h.Config.GetDeviceAndUserCodeLifespan(context).Seconds()))
		return false, nil
	}

	// The token calls were made too fast, we need to double the interval period
	expiration.NotUntil = h.getNotUntil(context, expiration.Counter+1)
	expiration.Counter += 1
	exp, err := h.serializeExpiration(expiration)
	if err != nil {
		return false, errorsx.WithStack(fosite.ErrServerError.WithHintf("Failed to serialize expiration struct %s", err))
	}
	h.RateLimiterCache.Set(keyBytes, exp, int(h.Config.GetDeviceAndUserCodeLifespan(context).Seconds()))

	return true, nil
}

func (h *DefaultDeviceStrategy) getNotUntil(context context.Context, multiplier int) time.Time {
	duration := h.Config.GetDeviceAuthTokenPollingInterval(context)
	expiration := time.Now().Add(duration * time.Duration(multiplier)).Add(-POLLING_RATE_LIMITING_LEEWAY)
	return expiration
}

type expirationTimer struct {
	NotUntil time.Time
	Counter  int
}

func (h *DefaultDeviceStrategy) serializeExpiration(exp *expirationTimer) ([]byte, error) {
	b, err := json.Marshal(exp)
	return b, err
}

func (h *DefaultDeviceStrategy) deserializeExpiration(b []byte) (*expirationTimer, error) {
	timer := new(expirationTimer)
	err := json.Unmarshal(b, timer)
	return timer, err
}
