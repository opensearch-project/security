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

import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;

import static org.opensearch.security.filter.SecurityRestFilter.HEALTH_SUFFIX;
import static org.opensearch.security.filter.SecurityRestFilter.PATTERN_PATH_PREFIX;
import static org.opensearch.security.filter.SecurityRestFilter.WHO_AM_I_SUFFIX;

import java.util.regex.Matcher;

import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestUtils;

public class SecurityRestUtils {
    public static String path(final String uri) {
        final int index = uri.indexOf('?');
        if (index >= 0) {
            return uri.substring(0, index);
        } else {
            return uri;
        }
    }

    public static boolean shouldSkipAuthentication(HttpRequest request) {
        String rawPath = path(request.uri());
        String path = RestUtils.decodeComponent(rawPath);
        Matcher matcher = PATTERN_PATH_PREFIX.matcher(path);
        final String suffix = matcher.matches() ? matcher.group(2) : null;

        boolean shouldSkipAuthentication = HttpMethod.OPTIONS.equals(request.method())
            || HEALTH_SUFFIX.equals(suffix)
            || WHO_AM_I_SUFFIX.equals(suffix);

        return shouldSkipAuthentication;
    }

    public static boolean shouldSkipAuthentication(SecurityRequestChannel request) {
        Matcher matcher = PATTERN_PATH_PREFIX.matcher(request.path());
        final String suffix = matcher.matches() ? matcher.group(2) : null;

        boolean shouldSkipAuthentication = (request.method() == Method.OPTIONS)
            || HEALTH_SUFFIX.equals(suffix)
            || WHO_AM_I_SUFFIX.equals(suffix);

        return shouldSkipAuthentication;
    }
}
