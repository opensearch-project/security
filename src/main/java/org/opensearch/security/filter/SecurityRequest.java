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

package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import javax.net.ssl.SSLEngine;

import org.opensearch.rest.RestRequest.Method;

/** How the security plugin interacts with requests */
public interface SecurityRequest {

    /** Collection of headers associated with the request */
    Map<String, List<String>> getHeaders();

    /** The SSLEngine associated with the request */
    SSLEngine getSSLEngine();

    /** The path of the request */
    String path();

    /** The method type of this request */
    Method method();

    /** The remote address of the request, possible null */
    Optional<InetSocketAddress> getRemoteAddress();

    /** The full uri of the request */
    String uri();

    /** Finds the first value of the matching header or null */
    default String header(final String headerName) {
        final Optional<Map<String, List<String>>> headersMap = Optional.ofNullable(getHeaders());
        return headersMap.map(headers -> headers.get(headerName)).map(List::stream).flatMap(Stream::findFirst).orElse(null);
    }

    /** The parameters associated with this request */
    Map<String, String> params();

    /** The list of parameters that have been accessed but not recorded as being consumed */
    Set<String> getUnconsumedParams();
}
