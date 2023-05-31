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

public class AuthenticatorUnavailableException extends RuntimeException {
    private static final long serialVersionUID = -7007025852090301416L;

    public AuthenticatorUnavailableException() {
        super();
    }

    public AuthenticatorUnavailableException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public AuthenticatorUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthenticatorUnavailableException(String message) {
        super(message);
    }

    public AuthenticatorUnavailableException(Throwable cause) {
        super(cause);
    }

}
