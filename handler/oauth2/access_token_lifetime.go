// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package oauth2

import "time"

// AccessTokenExpiresAt returns the expiry of an access token issued now with the given lifespan.
// The expiry is truncated to whole seconds: JWT iat is encoded in whole seconds, so rounding the
// expiry up could encode a lifetime one second longer than the configured lifespan.
func AccessTokenExpiresAt(lifespan time.Duration) time.Time {
	return time.Now().UTC().Add(lifespan).Truncate(time.Second)
}
