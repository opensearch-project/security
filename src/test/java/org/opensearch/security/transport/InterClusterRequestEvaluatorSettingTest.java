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

package org.opensearch.security.transport;

import org.junit.Test;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

/**
 * Validates the typed replacement setting introduced for
 * https://github.com/opensearch-project/security/issues/6479
 *
 * <p>The new setting {@code plugins.security.cert.intercluster_request_evaluator}
 * only accepts {@code default} or {@code oid}. Anything else must be rejected at
 * validation time so misconfigurations surface immediately rather than silently
 * changing trust semantics.
 */
public class InterClusterRequestEvaluatorSettingTest {

    /** Rebuilds the same Setting instance as OpenSearchSecurityPlugin registers, for isolated validation. */
    private static Setting<String> newSetting() {
        return Setting.simpleString(
            ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR,
            ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_DEFAULT,
            value -> {
                if (!ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_DEFAULT.equals(value)
                    && !ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_OID.equals(value)) {
                    throw new IllegalArgumentException("Unknown value '" + value + "'");
                }
            },
            Setting.Property.NodeScope,
            Setting.Property.Filtered
        );
    }

    @Test
    public void defaultValue_isDefault() {
        Setting<String> setting = newSetting();
        assertThat(setting.get(Settings.EMPTY), equalTo(ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_DEFAULT));
    }

    @Test
    public void accepts_default() {
        Setting<String> setting = newSetting();
        Settings s = Settings.builder()
            .put(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR, ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_DEFAULT)
            .build();
        assertThat(setting.get(s), equalTo(ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_DEFAULT));
    }

    @Test
    public void accepts_oid() {
        Setting<String> setting = newSetting();
        Settings s = Settings.builder()
            .put(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR, ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_OID)
            .build();
        assertThat(setting.get(s), equalTo(ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_OID));
    }

    @Test
    public void rejects_unknownValue() {
        Setting<String> setting = newSetting();
        Settings s = Settings.builder().put(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR, "nonsense").build();
        assertThrows(IllegalArgumentException.class, () -> setting.get(s));
    }
}
