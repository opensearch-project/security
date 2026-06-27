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

package org.opensearch.security.configuration;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.configuration.Salt.SALT_SIZE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SaltTest extends LuceneTestCase {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testDefault() {
        // act
        final Salt salt = Salt.from(Settings.EMPTY);

        // assert
        assertThat(salt.getSalt16().length, is(SALT_SIZE));
        assertArrayEquals(ConfigConstants.SECURITY_COMPLIANCE_SALT_DEFAULT.getBytes(StandardCharsets.UTF_8), salt.getSalt16());
    }

    @Test
    public void testDefaultSaltDoesNotLogWarningWithoutFieldMasking() {
        final List<String> warnings = captureWarnLogs(() -> {
            Salt.from(Settings.EMPTY);
            Salt.from(Settings.EMPTY);
            Salt.from(Settings.EMPTY);
        });

        assertThat(warnings, empty());
    }

    @Test
    public void testDefaultSaltRejectedInProductionWhenFieldMaskingConfigured() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Default compliance salt is not allowed in production when field masking is configured");

        // act
        Salt.validateSaltSettings(Settings.EMPTY, true);
    }

    @Test
    public void testDefaultSaltAllowedWhenFieldMaskingNotConfigured() {
        Salt.validateSaltSettings(Settings.EMPTY, false);
        Salt.validateSaltSettings(Settings.builder().put(ConfigConstants.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, true).build(), false);
    }

    @Test
    public void testDefaultSaltAllowedWithDemoFlagWhenFieldMaskingConfigured() {
        final List<String> warnings = captureWarnLogs(
            () -> Salt.validateSaltSettings(
                Settings.builder().put(ConfigConstants.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, true).build(),
                true
            )
        );

        assertThat(warnings.size(), is(1));
        assertTrue(warnings.get(0).contains("Field masking is configured"));
        assertTrue(warnings.get(0).contains(ConfigConstants.SECURITY_COMPLIANCE_SALT_DEFAULT));
    }

    @Test
    public void testIsFieldMaskingConfigured() throws Exception {
        final RoleV7 roleWithoutMasking = RoleV7.fromYamlString(
            "cluster_permissions:\n"
                + "  - 'cluster:monitor/health'\n"
                + "index_permissions:\n"
                + "  - index_patterns:\n"
                + "      - '*'\n"
                + "    allowed_actions:\n"
                + "      - 'read'"
        );
        final RoleV7 roleWithMasking = RoleV7.fromYamlString(
            "cluster_permissions:\n"
                + "  - 'cluster:monitor/health'\n"
                + "index_permissions:\n"
                + "  - index_patterns:\n"
                + "      - '*'\n"
                + "    masked_fields:\n"
                + "      - 'secret'\n"
                + "    allowed_actions:\n"
                + "      - 'read'"
        );

        final SecurityDynamicConfiguration<RoleV7> withoutMasking = SecurityDynamicConfiguration.empty(CType.ROLES);
        withoutMasking.putCEntry("role_a", roleWithoutMasking);

        final SecurityDynamicConfiguration<RoleV7> withMasking = SecurityDynamicConfiguration.empty(CType.ROLES);
        withMasking.putCEntry("role_b", roleWithMasking);

        assertFalse(Salt.isFieldMaskingConfigured(null));
        assertFalse(Salt.isFieldMaskingConfigured(withoutMasking));
        assertTrue(Salt.isFieldMaskingConfigured(withMasking));
    }

    @Test
    public void testConfig() {
        // arrange
        final String testSalt = "abcdefghijklmnop";
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_COMPLIANCE_SALT, testSalt).build();

        // act
        final Salt salt = Salt.from(settings);

        // assert
        assertArrayEquals(testSalt.getBytes(StandardCharsets.UTF_8), salt.getSalt16());
        assertThat(salt.getSalt16().length, is(SALT_SIZE));
    }

    @Test
    public void testSaltUsesOnlyFirst16Bytes() {
        // arrange
        final String testSalt = "abcdefghijklmnopqrstuvwxyz";
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_COMPLIANCE_SALT, testSalt).build();
        // act
        final Salt salt = Salt.from(settings);

        // assert
        assertThat(salt.getSalt16().length, is(SALT_SIZE));
        assertArrayEquals(testSalt.substring(0, SALT_SIZE).getBytes(StandardCharsets.UTF_8), salt.getSalt16());
    }

    @Test
    public void testSaltThrowsExceptionWhenInsufficientBytesProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt abcd must at least contain 16 bytes");

        // arrange
        final String testSalt = "abcd";
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_COMPLIANCE_SALT, testSalt).build();
        // act
        final Salt salt = Salt.from(settings);
    }

    @Test
    public void testSaltThrowsExceptionWhenInsufficientBytesArrayProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt must contain 16 bytes");

        // act
        new Salt(new byte[] { 1, 2, 3, 4, 5 });
    }

    @Test
    public void testSaltThrowsExceptionWhenExcessBytesArrayProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt must contain 16 bytes");

        // act
        new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5 });
    }

    @Test
    public void testSaltThrowsNoExceptionWhenCorrectBytesArrayProvided() {
        // act
        new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1 });
    }

    private static List<String> captureWarnLogs(Runnable action) {
        final Logger logger = (Logger) LogManager.getLogger(Salt.class);
        final var appender = new AbstractAppender(
            "SaltWarningCapture",
            null,
            PatternLayout.createDefaultLayout(),
            false,
            Property.EMPTY_ARRAY
        ) {
            private final java.util.List<LogEvent> events = new java.util.ArrayList<>();

            @Override
            public void append(LogEvent event) {
                events.add(event.toImmutable());
            }

            java.util.List<LogEvent> getEvents() {
                return events;
            }
        };
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.WARN);
        try {
            action.run();
            return appender.getEvents()
                .stream()
                .filter(e -> e.getLevel() == Level.WARN)
                .map(e -> e.getMessage().getFormattedMessage())
                .toList();
        } finally {
            logger.removeAppender(appender);
            appender.stop();
        }
    }
}
