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
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Covers the dynamic {@code nodes_dn} subscription concern in
 * https://github.com/opensearch-project/security/issues/6479
 *
 * <p>{@link DefaultInterClusterRequestEvaluator#subscribeForChanges(DynamicConfigFactory)} registers a listener only when
 * {@code plugins.security.nodes_dn_dynamic_config_enabled=true}, and the plugin must call it for every default evaluator,
 * including one produced by falling back from an unloadable legacy class name.
 */
public class InterClusterEvaluatorSubscriptionTest {

    @Test
    public void defaultEvaluator_subscribes_whenDynamicFlagEnabled() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true).build();
        DefaultInterClusterRequestEvaluator eval = new DefaultInterClusterRequestEvaluator(settings);
        DynamicConfigFactory dcf = mock(DynamicConfigFactory.class);

        eval.subscribeForChanges(dcf);

        verify(dcf, times(1)).registerDCFListener(eval);
    }

    @Test
    public void defaultEvaluator_doesNotSubscribe_whenDynamicFlagDisabled() {
        // Default value of SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED is false.
        DefaultInterClusterRequestEvaluator eval = new DefaultInterClusterRequestEvaluator(Settings.EMPTY);
        DynamicConfigFactory dcf = mock(DynamicConfigFactory.class);

        eval.subscribeForChanges(dcf);

        verify(dcf, never()).registerDCFListener(eval);
    }

    /**
     * The evaluator that replaces an unloadable legacy class keeps the dynamic nodes_dn setting, so it registers when
     * subscribed. That OpenSearchSecurityPlugin.createComponents actually subscribes it is checked against a running node in
     * InterClusterRequestEvaluatorWiringTest.
     */
    @Test
    public void fallbackFromUnloadableLegacyClass_subscribesWhenDynamicFlagEnabled() {
        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, "this.class.does.not.Exist")
            .put(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true)
            .build();

        InterClusterRequestEvaluator evaluator = InterClusterRequestEvaluatorFactory.create(settings);
        assertThat(evaluator, instanceOf(DefaultInterClusterRequestEvaluator.class));

        DynamicConfigFactory dcf = mock(DynamicConfigFactory.class);
        ((DefaultInterClusterRequestEvaluator) evaluator).subscribeForChanges(dcf);
        verify(dcf, times(1)).registerDCFListener(evaluator);
    }
}
