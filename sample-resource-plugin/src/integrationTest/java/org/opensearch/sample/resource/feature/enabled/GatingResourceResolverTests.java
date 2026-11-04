/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Tests a request whose access is governed by a resource it does not name. The sample plugin registers a
 * {@code GatingResourceResolver} for requests that address a resource by name: the id is known only after a lookup, which
 * the framework performs before the transport action runs.
 * <p>
 * The requesting user holds no cluster or index permission at all, so an allowed request can only have been allowed by
 * resource-level evaluation of the resolved resource.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GatingResourceResolverTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    private static final String SHARED_NAME = "alpha-resource";
    private static final String UNSHARED_NAME = "beta-resource";

    private String sharedResourceId;

    @Before
    public void setup() {
        sharedResourceId = api.createNamedSampleResourceAs(USER_ADMIN, SHARED_NAME);
        api.createNamedSampleResourceAs(USER_ADMIN, UNSHARED_NAME);
        api.awaitSharingEntry(sharedResourceId);
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void resolvedResourceShared_isAllowed() throws Exception {
        ok(() -> api.shareResource(sharedResourceId, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));

        TestRestClient.HttpResponse response = ok(() -> api.getResourceByName(SHARED_NAME, NO_ACCESS_USER));
        assertThat(response.getBody(), containsString(SHARED_NAME));
    }

    @Test
    public void resolvedResourceNotShared_isForbidden() throws Exception {
        ok(() -> api.shareResource(sharedResourceId, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));

        // the same request shape is allowed for the shared name, so the denial is about the resource the name resolves to
        ok(() -> api.getResourceByName(SHARED_NAME, NO_ACCESS_USER));
        forbidden(() -> api.getResourceByName(UNSHARED_NAME, NO_ACCESS_USER));
    }

    /**
     * A name that resolves to nothing is denied rather than falling through to the regular evaluator.
     */
    @Test
    public void unresolvableName_isForbidden() throws Exception {
        forbidden(() -> api.getResourceByName("no-such-resource", NO_ACCESS_USER));
    }

    /**
     * Names are not unique. When the user can see two resources with the same name, which one the request means is
     * unknown, so it is denied even though the user may read both.
     */
    @Test
    public void nameOfTwoVisibleResources_isForbidden() throws Exception {
        ok(() -> api.shareResource(sharedResourceId, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));
        String sameName = api.createNamedSampleResourceAs(USER_ADMIN, SHARED_NAME);
        api.awaitSharingEntry(sameName);
        ok(() -> api.shareResource(sameName, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));

        forbidden(() -> api.getResourceByName(SHARED_NAME, NO_ACCESS_USER));
    }

    /**
     * The lookup only sees resources the user may see, so a resource with the same name that is not shared with the user
     * neither makes the name ambiguous nor is ever served.
     */
    @Test
    public void nameAlsoUsedByAHiddenResource_servesTheVisibleOne() throws Exception {
        ok(() -> api.shareResource(sharedResourceId, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));
        api.awaitSharingEntry(api.createNamedSampleResourceAs(USER_ADMIN, SHARED_NAME));

        TestRestClient.HttpResponse response = ok(() -> api.getResourceByName(SHARED_NAME, NO_ACCESS_USER));
        assertThat(response.getBody(), containsString(SHARED_NAME));
    }

    @Test
    public void owner_isAllowed() throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResourceByName(UNSHARED_NAME, USER_ADMIN));
        assertThat(response.getBody(), containsString(UNSHARED_NAME));
        assertThat(response.getBody(), not(containsString(SHARED_NAME)));
    }
}
