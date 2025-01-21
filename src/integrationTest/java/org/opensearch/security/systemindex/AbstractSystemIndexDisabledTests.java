package org.opensearch.security.systemindex;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public abstract class AbstractSystemIndexDisabledTests {

    private final LocalCluster cluster;

    protected AbstractSystemIndexDisabledTests(LocalCluster cluster) {
        this.cluster = cluster;
    }

    @Before
    public void setup() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(".system-index1");
        }
    }

    @Test
    public void testPluginShouldBeAbleToIndexIntoAnySystemIndexWhenProtectionIsDisabled() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.put(".system-index1");
            client.put(".system-index2");
        }
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-mixed-index");

            response.assertStatusCode(RestStatus.OK.getStatus());

            assertThat(
                response.getBody(),
                not(
                    containsString(
                        "no permissions for [] and User [name=plugin:org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1"
                    )
                )
            );
        }
    }
}
