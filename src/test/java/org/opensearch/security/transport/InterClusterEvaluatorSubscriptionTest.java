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
import org.opensearch.security.support.ReflectionHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Reproducer for the second concern in
 * https://github.com/opensearch-project/security/issues/6479
 *
 * <p>The default evaluator subscribes to dynamic {@code nodes_dn} updates via
 * {@link DefaultInterClusterRequestEvaluator#subscribeForChanges(DynamicConfigFactory)}
 * only when {@code plugins.security.nodes_dn_dynamic_config_enabled=true} AND the
 * plugin selects the default class by name (see the {@code createComponents}
 * branch in {@code OpenSearchSecurityPlugin}). Configuring a custom FQCN — even
 * one that silently falls back to the default instance because it fails to load
 * — bypasses the subscription branch, silently changing trust semantics.
 *
 * <p>These tests pin each half of the compound bug:
 * <ol>
 *   <li>{@link DefaultInterClusterRequestEvaluator#subscribeForChanges} actually
 *       registers a listener when the dynamic flag is on, and does not when it
 *       is off.</li>
 *   <li>Simulating the plugin branch: when the setting points at an unloadable
 *       FQCN, {@link ReflectionHelper} returns a default instance, but the
 *       plugin's string-equality gate skips the subscription call.</li>
 * </ol>
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
     * Mirrors the exact string-equality branch in
     * {@code OpenSearchSecurityPlugin.createComponents}:
     *
     * <pre>{@code
     * if (DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS.equals(className)) {
     *     ((DefaultInterClusterRequestEvaluator) evaluator).subscribeForChanges(dcf);
     * }
     * }</pre>
     *
     * Demonstrates that when the FQCN setting is non-default but fails to load,
     * (a) the resulting instance IS a {@link DefaultInterClusterRequestEvaluator}
     * (silent fallback), yet (b) the branch below sees a non-default class name
     * and skips the subscribe call. Net effect: default evaluator runs without
     * ever receiving nodes_dn updates.
     */
    @Test
    public void pluginBranch_skipsSubscribe_whenFqcnNonDefault_evenIfFallsBackToDefault() {
        final String DEFAULT_CLASS = DefaultInterClusterRequestEvaluator.class.getName();
        final String customFqcn = "this.class.does.not.Exist";

        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, customFqcn)
            .put(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true) // even with dynamic ON
            .build();

        String className = settings.get(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, DEFAULT_CLASS);
        InterClusterRequestEvaluator evaluator = new DefaultInterClusterRequestEvaluator(settings);
        if (!DEFAULT_CLASS.equals(className)) {
            evaluator = ReflectionHelper.instantiateInterClusterRequestEvaluator(className, settings);
        }
        // (a) silent fallback -> a Default instance ...
        assertThat(evaluator, instanceOf(DefaultInterClusterRequestEvaluator.class));

        // (b) ... but the string-equality gate skips subscribe.
        DynamicConfigFactory dcf = mock(DynamicConfigFactory.class);
        if (DEFAULT_CLASS.equals(className)) {
            ((DefaultInterClusterRequestEvaluator) evaluator).subscribeForChanges(dcf);
        }
        verify(dcf, never()).registerDCFListener(evaluator);
    }
}
