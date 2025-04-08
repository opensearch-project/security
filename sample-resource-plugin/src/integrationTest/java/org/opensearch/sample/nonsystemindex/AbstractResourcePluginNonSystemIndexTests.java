/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.nonsystemindex;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.AbstractSampleResourcePluginTests;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.nonsystemindex.plugin.ResourceNonSystemIndexPlugin.SAMPLE_NON_SYSTEM_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This abstract class defines common tests between different feature flag scenarios where resource plugin does not register its resource index as system index
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public abstract class AbstractResourcePluginNonSystemIndexTests extends AbstractSampleResourcePluginTests {

    protected abstract LocalCluster getLocalCluster();

    private LocalCluster cluster;
    ResourcePluginInfo resourcePluginInfo;

    @Before
    public void setup() {
        cluster = getLocalCluster();
        resourcePluginInfo = cluster.nodes().getFirst().getInjectable(ResourcePluginInfo.class);
    }

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(SAMPLE_NON_SYSTEM_INDEX_NAME);
            client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX);
            resourcePluginInfo.getResourceIndicesMutable().remove(SAMPLE_NON_SYSTEM_INDEX_NAME);
            resourcePluginInfo.getResourceProvidersMutable().remove(SAMPLE_NON_SYSTEM_INDEX_NAME);
        }
    }

    @Test
    public void testPluginInstalledCorrectly() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse pluginsResponse = client.get("_cat/plugins");
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.security.OpenSearchSecurityPlugin"));
            assertThat(
                pluginsResponse.getBody(),
                containsString("org.opensearch.sample.nonsystemindex.plugin.ResourceNonSystemIndexPlugin")
            );
        }
    }
}
