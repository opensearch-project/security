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
package org.opensearch.security.authtoken.jwt;

import java.util.Date;

import org.opensearch.identity.tokens.BearerAuthToken;

public class ExpiringBearerAuthToken extends BearerAuthToken {
    private final String subject;
    private final Date expiry;
    private final long expiresInSeconds;

    public ExpiringBearerAuthToken(final String serializedToken, final String subject, final Date expiry, final long expiresInSeconds) {
        super(serializedToken);
        this.subject = subject;
        this.expiry = expiry;
        this.expiresInSeconds = expiresInSeconds;
    }

    public String getSubject() {
        return subject;
    }

    public Date getExpiry() {
        return expiry;
    }

    public long getExpiresInSeconds() {
        return expiresInSeconds;
    }
}
