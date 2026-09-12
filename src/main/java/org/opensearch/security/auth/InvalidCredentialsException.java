/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import org.opensearch.OpenSearchSecurityException;

/**
 * Thrown by {@link org.opensearch.security.auth.internal.InternalAuthenticationBackend#authenticate(org.opensearch.security.auth.AuthenticationContext)}
 * when credentials are definitively invalid (user does not exist, password
 * mismatch, empty password).
 *
 * <p>Distinct from the generic {@link OpenSearchSecurityException} to let
 * {@link org.opensearch.security.auth.BackendRegistry} populate its negative
 * authentication cache only for definitive credential failures, without
 * relying on fragile substring matching on the exception message. Transient
 * backend errors (e.g., "Internal authentication backend not configured"
 * during startup/reload) continue to throw plain OpenSearchSecurityException
 * and are not cached.
 */
public class InvalidCredentialsException extends OpenSearchSecurityException {

    private static final long serialVersionUID = 1L;

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
