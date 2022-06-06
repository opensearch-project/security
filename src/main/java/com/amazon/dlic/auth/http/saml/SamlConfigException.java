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

package com.amazon.dlic.auth.http.saml;

public class SamlConfigException extends Exception {

    private static final long serialVersionUID = 6888715101647475455L;

    public SamlConfigException() {
        super();
    }

    public SamlConfigException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public SamlConfigException(String message, Throwable cause) {
        super(message, cause);
    }

    public SamlConfigException(String message) {
        super(message);
    }

    public SamlConfigException(Throwable cause) {
        super(cause);
    }

}
