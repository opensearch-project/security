/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;

public class AuditHeaderUtilsTest {

    private static final Map<String, List<String>> HEADERS = Map.of(
        "Authorization",
        List.of("Bearer token"),
        "Proxy-Authorization",
        List.of("Basic abc"),
        "cookie",
        List.of("session=abc"),
        "Set-Cookie",
        List.of("session=abc"),
        "X-Auth-Token",
        List.of("abc"),
        "User-Agent",
        List.of("curl/8.0")
    );

    private static AuditConfig.Filter filterWithExcludeSensitiveHeaders(final boolean exclude) {
        return AuditConfig.Filter.from(
            Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, exclude).build()
        );
    }

    @Test
    public void stripsSensitiveHeadersCaseInsensitivelyWhenEnabled() {
        // exclude_sensitive_headers defaults to true
        final Map<String, List<String>> filtered = AuditHeaderUtils.filterHeaders(HEADERS, AuditConfig.Filter.from(Settings.EMPTY));

        assertThat(filtered, not(hasKey("Authorization")));
        assertThat(filtered, not(hasKey("Proxy-Authorization")));
        assertThat(filtered, not(hasKey("cookie")));
        assertThat(filtered, not(hasKey("Set-Cookie")));
        assertThat(filtered, not(hasKey("X-Auth-Token")));
        // non-sensitive headers are retained
        assertThat(filtered, hasKey("User-Agent"));
    }

    @Test
    public void retainsAllHeadersWhenExcludeSensitiveHeadersDisabled() {
        final Map<String, List<String>> filtered = AuditHeaderUtils.filterHeaders(HEADERS, filterWithExcludeSensitiveHeaders(false));

        assertThat(filtered, hasKey("Authorization"));
        assertThat(filtered, hasKey("cookie"));
        assertThat(filtered, hasKey("X-Auth-Token"));
        assertThat(filtered, hasKey("User-Agent"));
    }

    @Test
    public void returnsEmptyMapForNullOrEmptyHeaders() {
        assertThat(AuditHeaderUtils.filterHeaders(null, AuditConfig.Filter.from(Settings.EMPTY)), anEmptyMap());
        assertThat(AuditHeaderUtils.filterHeaders(Map.of(), AuditConfig.Filter.from(Settings.EMPTY)), anEmptyMap());
    }
}
