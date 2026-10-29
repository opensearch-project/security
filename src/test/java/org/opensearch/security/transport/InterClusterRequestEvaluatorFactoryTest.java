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

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertThrows;

public class InterClusterRequestEvaluatorFactoryTest {

    private static InterClusterRequestEvaluator create(final String... kvPairs) {
        final Settings.Builder builder = Settings.builder();
        for (int i = 0; i < kvPairs.length; i += 2) {
            builder.put(kvPairs[i], kvPairs[i + 1]);
        }
        return InterClusterRequestEvaluatorFactory.create(builder.build());
    }

    @Test
    public void nothingConfigured_usesDefault() {
        assertThat(create(), instanceOf(DefaultInterClusterRequestEvaluator.class));
    }

    @Test
    public void typedDefault_usesDefault() {
        assertThat(
            create(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR, ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_DEFAULT),
            instanceOf(DefaultInterClusterRequestEvaluator.class)
        );
    }

    @Test
    public void typedOid_usesOid() {
        assertThat(
            create(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR, ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_OID),
            instanceOf(OIDClusterRequestEvaluator.class)
        );
    }

    @Test
    public void typedUnknownValue_isRejected() {
        assertThrows(
            IllegalArgumentException.class,
            () -> create(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR, OIDClusterRequestEvaluator.class.getName())
        );
    }

    @Test
    public void legacyDefaultClass_usesDefault() {
        assertThat(
            create(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, DefaultInterClusterRequestEvaluator.class.getName()),
            instanceOf(DefaultInterClusterRequestEvaluator.class)
        );
    }

    @Test
    public void legacyOidClass_usesOid() {
        assertThat(
            create(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, OIDClusterRequestEvaluator.class.getName()),
            instanceOf(OIDClusterRequestEvaluator.class)
        );
    }

    @Test
    public void legacyUnloadableClass_fallsBackToDefault() {
        assertThat(
            create(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, "this.class.does.not.Exist"),
            instanceOf(DefaultInterClusterRequestEvaluator.class)
        );
    }

    @Test
    public void legacyEmptyValue_isIgnored() {
        assertThat(
            create(
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                "",
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR,
                ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_OID
            ),
            instanceOf(OIDClusterRequestEvaluator.class)
        );
    }

    @Test
    public void bothConfigured_typedSettingWins() {
        assertThat(
            create(
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                OIDClusterRequestEvaluator.class.getName(),
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR,
                ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_DEFAULT
            ),
            instanceOf(DefaultInterClusterRequestEvaluator.class)
        );
        assertThat(
            create(
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                DefaultInterClusterRequestEvaluator.class.getName(),
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR,
                ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_OID
            ),
            instanceOf(OIDClusterRequestEvaluator.class)
        );
    }
}
