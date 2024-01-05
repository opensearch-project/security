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

package org.opensearch.security.auditlog.config;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.config.AuditConfig.Filter.FilterEntries;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static org.opensearch.security.auditlog.impl.AuditCategory.BAD_HEADERS;
import static org.opensearch.security.auditlog.impl.AuditCategory.FAILED_LOGIN;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditCategory.MISSING_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditCategory.SSL_EXCEPTION;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class AuditConfigFilterTest {

    @Test
    public void testDefault() {
        // arrange
        final WildcardMatcher defaultIgnoredUserMatcher = WildcardMatcher.from("kibanaserver");
        final EnumSet<AuditCategory> defaultDisabledCategories = EnumSet.of(AUTHENTICATED, GRANTED_PRIVILEGES);
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(Settings.EMPTY);
        // assert
        assertTrue(auditConfigFilter.isRestApiAuditEnabled());
        assertTrue(auditConfigFilter.isTransportApiAuditEnabled());
        assertTrue(auditConfigFilter.shouldLogRequestBody());
        assertTrue(auditConfigFilter.shouldResolveIndices());
        assertFalse(auditConfigFilter.shouldResolveBulkRequests());
        assertTrue(auditConfigFilter.shouldExcludeSensitiveHeaders());
        assertSame(WildcardMatcher.NONE, auditConfigFilter.getIgnoredAuditRequestsMatcher());
        assertEquals(defaultIgnoredUserMatcher, auditConfigFilter.getIgnoredAuditUsersMatcher());
        assertSame(WildcardMatcher.NONE, auditConfigFilter.getIgnoredCustomHeadersMatcher());
        assertEquals(auditConfigFilter.getDisabledRestCategories(), defaultDisabledCategories);
        assertEquals(auditConfigFilter.getDisabledTransportCategories(), defaultDisabledCategories);
    }

    @Test
    public void testConfig() {
        // arrange
        final Settings settings = Settings.builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, false)
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, "test-request")
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "test-user")
            .putList(ConfigConstants.SECURITY_AUDIT_IGNORE_HEADERS, "test-header")
            .putList(
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                BAD_HEADERS.toString(),
                SSL_EXCEPTION.toString()
            )
            .putList(
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                FAILED_LOGIN.toString(),
                MISSING_PRIVILEGES.toString()
            )
            .build();
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertFalse(auditConfigFilter.isRestApiAuditEnabled());
        assertFalse(auditConfigFilter.isTransportApiAuditEnabled());
        assertFalse(auditConfigFilter.shouldLogRequestBody());
        assertFalse(auditConfigFilter.shouldResolveIndices());
        assertTrue(auditConfigFilter.shouldResolveBulkRequests());
        assertFalse(auditConfigFilter.shouldExcludeSensitiveHeaders());
        assertEquals(WildcardMatcher.from(Collections.singleton("test-user")), auditConfigFilter.getIgnoredAuditUsersMatcher());
        assertEquals(WildcardMatcher.from(Collections.singleton("test-request")), auditConfigFilter.getIgnoredAuditRequestsMatcher());
        assertEquals(WildcardMatcher.from(Collections.singleton("test-header")), auditConfigFilter.getIgnoredCustomHeadersMatcher());
        assertEquals(auditConfigFilter.getDisabledRestCategories(), EnumSet.of(BAD_HEADERS, SSL_EXCEPTION));
        assertEquals(auditConfigFilter.getDisabledTransportCategories(), EnumSet.of(FAILED_LOGIN, MISSING_PRIVILEGES));
    }

    @Test
    public void testNone() {
        // arrange
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "NONE")
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "None")
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "none")
            .build();
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertSame(WildcardMatcher.NONE, auditConfigFilter.getIgnoredAuditUsersMatcher());
        assertTrue(auditConfigFilter.getDisabledRestCategories().isEmpty());
        assertTrue(auditConfigFilter.getDisabledTransportCategories().isEmpty());
    }

    @Test
    public void testEmpty() {
        // arrange
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, Collections.emptyList())
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, Collections.emptyList())
            .putList(ConfigConstants.SECURITY_AUDIT_IGNORE_HEADERS, Collections.emptyList())
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, Collections.emptyList())
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, Collections.emptyList())
            .build();
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertSame(WildcardMatcher.NONE, auditConfigFilter.getIgnoredAuditUsersMatcher());
        assertTrue(auditConfigFilter.getDisabledRestCategories().isEmpty());
        assertTrue(auditConfigFilter.getDisabledTransportCategories().isEmpty());
    }

    @Test
    public void testFilterEntries() {
        assertThat(FilterEntries.ENABLE_REST.getKey(), equalTo("enable_rest"));
        assertThat(FilterEntries.ENABLE_REST.getKeyWithNamespace(), equalTo("plugins.security.audit.config.enable_rest"));
        assertThat(FilterEntries.ENABLE_REST.getLegacyKeyWithNamespace(), equalTo("opendistro_security.audit.enable_rest"));
    }

    @Test
    public void fromSettingBoolean() {
        final FilterEntries entry = FilterEntries.ENABLE_REST;

        // Use primary key
        final Settings settings1 = Settings.builder()
            .put(entry.getKeyWithNamespace(), false)
            .put(entry.getLegacyKeyWithNamespace(), true)
            .build();
        assertThat(AuditConfig.Filter.fromSettingBoolean(settings1, entry, true), equalTo(false));

        // Use fallback key
        final Settings settings2 = Settings.builder().put(entry.getLegacyKeyWithNamespace(), false).build();
        assertThat(AuditConfig.Filter.fromSettingBoolean(settings2, entry, true), equalTo(false));

        // Use default
        assertThat(AuditConfig.Filter.fromSettingBoolean(Settings.builder().build(), entry, true), equalTo(true));
    }

    @Test
    public void fromSettingStringSet() {
        final FilterEntries entry = FilterEntries.IGNORE_USERS;

        // Use primary key
        final Settings settings1 = Settings.builder()
            .putList(entry.getKeyWithNamespace(), "abc")
            .putList(entry.getLegacyKeyWithNamespace(), "def")
            .build();
        assertThat(AuditConfig.Filter.fromSettingStringSet(settings1, entry, List.of("xyz")), equalTo(ImmutableSet.of("abc")));

        // Use fallback key
        final Settings settings2 = Settings.builder().putList(entry.getLegacyKeyWithNamespace(), "def").build();
        assertThat(AuditConfig.Filter.fromSettingStringSet(settings2, entry, List.of("xyz")), equalTo(ImmutableSet.of("def")));

        // Use default
        assertThat(
            AuditConfig.Filter.fromSettingStringSet(Settings.builder().build(), entry, List.of("xyz")),
            equalTo(ImmutableSet.of("xyz"))
        );
    }

    @Test
    public void fromSettingParseAuditCategory() {
        final FilterEntries entry = FilterEntries.DISABLE_REST_CATEGORIES;
        final Function<Settings, Set<AuditCategory>> parse = (settings) -> AuditCategory.parse(
            AuditConfig.Filter.fromSettingStringSet(settings, entry, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT)
        );

        final Settings noValues = Settings.builder().build();
        assertThat(parse.apply(noValues), equalTo(ImmutableSet.of(AUTHENTICATED, GRANTED_PRIVILEGES)));

        final Settings legacySettingNone = Settings.builder().put(entry.getLegacyKeyWithNamespace(), "NONE").build();
        assertThat(parse.apply(legacySettingNone), equalTo(ImmutableSet.of()));

        final Settings legacySettingValue = Settings.builder().put(entry.getLegacyKeyWithNamespace(), AUTHENTICATED.name()).build();
        assertThat(parse.apply(legacySettingValue), equalTo(ImmutableSet.of(AUTHENTICATED)));

        final Settings legacySettingMultipleValues = Settings.builder()
            .putList(entry.getLegacyKeyWithNamespace(), AUTHENTICATED.name(), BAD_HEADERS.name())
            .build();
        assertThat(parse.apply(legacySettingMultipleValues), equalTo(ImmutableSet.of(AUTHENTICATED, BAD_HEADERS)));

        final Settings settingNone = Settings.builder()
            .put(entry.getKeyWithNamespace(), "NONE")
            .put(entry.getLegacyKeyWithNamespace(), FAILED_LOGIN.name())
            .build();
        assertThat(parse.apply(settingNone), equalTo(ImmutableSet.of()));

        final Settings settingValue = Settings.builder()
            .put(entry.getKeyWithNamespace(), AUTHENTICATED.name())
            .put(entry.getLegacyKeyWithNamespace(), FAILED_LOGIN.name())
            .build();
        assertThat(parse.apply(settingValue), equalTo(ImmutableSet.of(AUTHENTICATED)));

        final Settings settingMultipleValues = Settings.builder()
            .putList(entry.getKeyWithNamespace(), AUTHENTICATED.name(), BAD_HEADERS.name())
            .put(entry.getLegacyKeyWithNamespace(), FAILED_LOGIN.name())
            .build();
        assertThat(parse.apply(settingMultipleValues), equalTo(ImmutableSet.of(AUTHENTICATED, BAD_HEADERS)));

        final Settings settingMultipleValuesString = Settings.builder()
            .put(entry.getKeyWithNamespace(), AUTHENTICATED.name() + "," + BAD_HEADERS.name())
            .put(entry.getLegacyKeyWithNamespace(), FAILED_LOGIN.name())
            .build();
        assertThat(parse.apply(settingMultipleValues), equalTo(ImmutableSet.of(AUTHENTICATED, BAD_HEADERS)));
    }
}
