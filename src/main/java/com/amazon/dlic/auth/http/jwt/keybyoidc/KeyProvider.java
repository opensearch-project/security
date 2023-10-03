/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import com.nimbusds.jose.jwk.JWK;

public interface KeyProvider {
    JWK getKey(String kid) throws AuthenticatorUnavailableException, BadCredentialsException;

    JWK getKeyAfterRefresh(String kid) throws AuthenticatorUnavailableException, BadCredentialsException;
}
