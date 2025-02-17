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

package org.opensearch.security.ssl.config;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;

public enum CertType {
    HTTP(SSL_HTTP_PREFIX),
    TRANSPORT(SSL_TRANSPORT_PREFIX),
    TRANSPORT_CLIENT(SSL_TRANSPORT_CLIENT_PREFIX);

    public static Set<String> TYPES = Arrays.stream(CertType.values())
        .map(CertType::name)
        .map(String::toLowerCase)
        .collect(Collectors.toSet());

    private final String sslConfigPrefix;

    private CertType(String sslConfigPrefix) {
        this.sslConfigPrefix = sslConfigPrefix;
    }

    public String sslConfigPrefix() {
        return sslConfigPrefix;
    }

}
