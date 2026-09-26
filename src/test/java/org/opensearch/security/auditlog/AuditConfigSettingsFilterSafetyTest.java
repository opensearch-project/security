/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.auditlog;

import java.util.regex.Pattern;

import org.junit.Test;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

/**
 * Safety net: every setting registered under {@code plugins.security.audit.config.*} whose key
 * contains a secret-ish substring MUST carry {@link Setting.Property#Filtered}. In SSL-only mode
 * the broad wildcard filter no longer covers this subtree, so individual {@code Property.Filtered}
 * annotations are the only thing keeping credentials out of unauthenticated settings responses.
 *
 * If this test fails you likely added a new sink credential under {@code config.*} without
 * {@code Property.Filtered} — add it and see the comment in
 * {@code OpenSearchSecurityPlugin#getSettings()} at the "Security - Audit - Sink" block.
 */
public class AuditConfigSettingsFilterSafetyTest {

    @Test
    public void allSensitiveConfigSettingsAreFiltered() {
        Settings disabled = Settings.builder().put(ConfigConstants.SECURITY_DISABLED, true).build();
        // Matches credential-bearing or security-sensitive key suffixes under config.*.
        // Intentionally broad to catch new sink credentials added without Property.Filtered.
        // If this test fails on a genuinely non-secret key, add it to an exclusion list
        // rather than weakening the pattern.
        Pattern secretish = Pattern.compile(
            "password|username|token|webhook|pemkey|pemcert|pemtrustedcas"
                + "|salt|jks|http_endpoints|ssl_|cert_alias|keystore|truststore|pkcs|secret"
        );

        for (Setting<?> s : new OpenSearchSecurityPlugin(disabled, null).getSettings()) {
            String key = s.getKey();
            if (key.startsWith(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX) && secretish.matcher(key).find()) {
                assertThat(key + " must be Property.Filtered", s.getProperties().contains(Setting.Property.Filtered), equalTo(true));
            }
        }
    }
}
