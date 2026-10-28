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

import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.RuleChain;

import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.LocalOpenSearchCluster;
import org.opensearch.test.framework.log.LogsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * Checks how OpenSearchSecurityPlugin.createComponents wires the inter-cluster request evaluator when the deprecated class-name
 * setting points at a class that cannot be loaded. See https://github.com/opensearch-project/security/issues/6479
 */
public class InterClusterRequestEvaluatorWiringTest {

    private static final LogsRule deprecationLogs = new LogsRule(
        "org.opensearch.deprecation.security.transport.InterClusterRequestEvaluatorFactory"
    );

    private static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                "this.class.does.not.Exist",
                ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED,
                true
            )
        )
        .build();

    // The warnings are logged while the node starts, so capture logs around cluster startup
    @ClassRule
    public static final RuleChain rules = RuleChain.outerRule(deprecationLogs).around(cluster);

    @Test
    public void fallbackEvaluatorFromUnloadableLegacyClassSubscribesToNodesDnUpdates() {
        final LocalOpenSearchCluster.Node node = cluster.nodes().get(0);
        final InterClusterRequestEvaluator evaluator = node.getInjectable(SecurityInterceptor.class).getInterClusterRequestEvaluator();

        assertThat(evaluator, instanceOf(DefaultInterClusterRequestEvaluator.class));
        assertThat(
            "createComponents must subscribe the fallback evaluator to dynamic nodes_dn updates",
            node.getInjectable(DynamicConfigFactory.class).isDCFListenerRegistered(evaluator),
            is(true)
        );
    }

    @Test
    public void legacySettingLogsMigrationHint() {
        deprecationLogs.assertThatContain("Custom inter-cluster request evaluators will not be supported");
    }
}
