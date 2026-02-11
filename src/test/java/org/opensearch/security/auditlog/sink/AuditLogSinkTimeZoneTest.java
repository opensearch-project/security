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

package org.opensearch.security.auditlog.sink;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.helper.LoggingSink;
import org.opensearch.security.support.ConfigConstants;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;

import static org.junit.Assert.assertEquals;

public class AuditLogSinkTimeZoneTest {

    private static final long FIXED_UTC_MILLIS = new DateTime(2026, 1, 28, 10, 0, DateTimeZone.UTC).getMillis();
    private static final String MY_INDEX = "my-index";
    private static final String DATE_FORMAT_PATTERN = "yyyy-MM-dd-HH-mm";

    @Before
    public void freezeTime() {
        DateTimeUtils.setCurrentMillisFixed(FIXED_UTC_MILLIS);
    }

    @After
    public void resetTime() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void testValidTimezoneUsesConfiguredTimezone() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_AUDIT_CONFIG_TIMEZONE, "Europe/Rome").build();
        LoggingSink sink = createSink(settings);

        String expected = "2026-01-28-11-00"; // 10:00 UTC +1h = 11:00
        String actual = sink.getExpandedIndexName(DateTimeFormat.forPattern(DATE_FORMAT_PATTERN), MY_INDEX);

        assertEquals(expected, actual);
    }

    @Test
    public void testInvalidTimezoneFallsBackToUTC() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_AUDIT_CONFIG_TIMEZONE, "Invalid/Zone").build();
        LoggingSink sink = createSink(settings);

        String expected = "2026-01-28-10-00";
        String actual = sink.getExpandedIndexName(DateTimeFormat.forPattern(DATE_FORMAT_PATTERN), MY_INDEX);

        assertEquals(expected, actual);
    }

    @Test
    public void testDefaultTimezoneIsUTC() {
        LoggingSink sink = createSink(Settings.builder().build());

        String expected = "2026-01-28-10-00"; // UTC
        String actual = sink.getExpandedIndexName(DateTimeFormat.forPattern(DATE_FORMAT_PATTERN), MY_INDEX);

        assertEquals(expected, actual);
    }

    @Test
    public void testNullPatternReturnsOriginalIndex() {
        LoggingSink sink = createSink(Settings.builder().build());
        assertEquals(MY_INDEX, sink.getExpandedIndexName(null, MY_INDEX));
    }

    @Test
    public void testTimezonePlusThreeAndHalfHours() {
        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_AUDIT_CONFIG_TIMEZONE, "Asia/Tehran") // UTC+3:30
            .build();
        LoggingSink sink = createSink(settings);

        String expected = "2026-01-28-13-30"; // 10:00 UTC +3:30
        String actual = sink.getExpandedIndexName(DateTimeFormat.forPattern(DATE_FORMAT_PATTERN), MY_INDEX);

        assertEquals(expected, actual);
    }

    @Test
    public void testTimezoneMinusThreeAndHalfHours() {
        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_AUDIT_CONFIG_TIMEZONE, "America/St_Johns") // UTC-3:30
            .build();
        LoggingSink sink = createSink(settings);

        String expected = "2026-01-28-06-30"; // 10:00 UTC -3:30
        String actual = sink.getExpandedIndexName(DateTimeFormat.forPattern(DATE_FORMAT_PATTERN), MY_INDEX);

        assertEquals(expected, actual);
    }

    private LoggingSink createSink(Settings settings) {
        return new LoggingSink("test", settings, ConfigConstants.SECURITY_SETTINGS_PREFIX, null);
    }
}
