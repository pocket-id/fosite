// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/ory/x/errorsx"
)

// GetResourceIndicator extracts a single RFC 8707 resource value from a form.
func GetResourceIndicator(form url.Values) (string, error) {
	values := form["resource"]
	if len(values) > 1 {
		return "", errorsx.WithStack(ErrInvalidTarget.WithHint("Only a single 'resource' parameter is supported."))
	}
	if len(values) == 0 {
		return "", nil
	}
	return values[0], nil
}

// ValidateResourceIndicator validates and returns the single RFC 8707 resource value from a form.
func ValidateResourceIndicator(form url.Values) (string, error) {
	resource, err := GetResourceIndicator(form)
	if err != nil {
		return "", err
	}
	if resource == "" {
		return "", nil
	}
	if !IsValidResourceIndicatorURI(resource) {
		return "", errorsx.WithStack(ErrInvalidTarget.WithHintf("The requested resource '%s' is invalid, missing, unknown, or malformed.", resource))
	}

	return resource, nil
}

// GetResourceIndicators returns every RFC 8707 resource value of a form in request order, or nil if there is none.
// Unlike GetResourceIndicator it never fails, and it does not validate the values.
func GetResourceIndicators(form url.Values) []string {
	return slices.Clone(form["resource"])
}

// ValidateResourceIndicators validates and returns the RFC 8707 resource values of a form.
//
// RFC 8707 Section 2 allows a client to repeat the "resource" parameter, but lets the authorization server refuse
// to fulfil a request with several of them. With allowMultiple false this behaves exactly like
// ValidateResourceIndicator: repeated values are rejected with invalid_target. With allowMultiple true every
// value must be an absolute URI without a fragment, and all of them are returned in request order. Duplicates are
// not removed: deciding whether two spellings name the same resource is up to the caller.
func ValidateResourceIndicators(form url.Values, allowMultiple bool) ([]string, error) {
	if len(form["resource"]) <= 1 || !allowMultiple {
		resource, err := ValidateResourceIndicator(form)
		if err != nil || resource == "" {
			return nil, err
		}
		return []string{resource}, nil
	}

	for _, resource := range form["resource"] {
		if !IsValidResourceIndicatorURI(resource) {
			return nil, errorsx.WithStack(ErrInvalidTarget.WithHintf("The requested resource '%s' is invalid, missing, unknown, or malformed.", resource))
		}
	}

	return GetResourceIndicators(form), nil
}

// IsValidResourceIndicatorURI reports whether raw is an absolute RFC 8707 resource URI without a fragment component.
func IsValidResourceIndicatorURI(raw string) bool {
	if raw == "" || strings.Contains(raw, "#") || strings.ContainsFunc(raw, unicode.IsSpace) {
		return false
	}

	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	return u.IsAbs()
}

// IsValidScopeToken reports whether scope is a valid RFC 6749 scope-token.
func IsValidScopeToken(scope string) bool {
	if scope == "" {
		return false
	}

	for i := 0; i < len(scope); i++ {
		c := scope[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) {
			continue
		}
		return false
	}

	return true
}
