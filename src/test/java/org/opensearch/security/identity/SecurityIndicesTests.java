package org.opensearch.security.identity;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.service.ClusterService;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.opensearch.security.identity.SecurityIndices.SCHEDULED_JOB_IDENTITY_INDEX;
import static org.opensearch.security.identity.SecurityIndicesTestUtils.createNodeClient;

@RunWith(MockitoJUnitRunner.class)
public class SecurityIndicesTests {

    @Mock
    private ClusterService clusterService;

    @Mock
    private Client client;

    @Test
    public void testScheduledJobIdentityIndexNotExists() throws Exception {
        doReturn(
            SecurityIndicesTestUtils.createClusterState(
                new SecurityIndicesTestUtils.IndexShorthand("my-index", IndexAbstraction.Type.CONCRETE_INDEX)
            )
        ).when(clusterService).state();
        SecurityIndices indices = new SecurityIndices(client, clusterService);

        boolean exists = indices.doesScheduledJobIdentityIndexExists();
        assertFalse(exists);
    }

    @Test
    public void testScheduledJobIdentityIndexExists() throws Exception {
        doReturn(
            SecurityIndicesTestUtils.createClusterState(
                new SecurityIndicesTestUtils.IndexShorthand(SCHEDULED_JOB_IDENTITY_INDEX, IndexAbstraction.Type.CONCRETE_INDEX)
            )
        ).when(clusterService).state();
        SecurityIndices indices = new SecurityIndices(client, clusterService);

        boolean exists = indices.doesScheduledJobIdentityIndexExists();
        assertTrue(exists);
    }

    @Test
    public void testInitScheduledJobIdentityIndex() throws Exception {
        Client nodeClient = createNodeClient();
        SecurityIndices indices = new SecurityIndices(nodeClient, clusterService);
        ActionListener actionListener = new ActionListener<CreateIndexResponse>() {
            @Override
            public void onResponse(CreateIndexResponse createIndexResponse) {}

            @Override
            public void onFailure(Exception e) {}
        };
        indices.initScheduledJobIdentityIndex(actionListener);

        verify(nodeClient).admin();
        verify(nodeClient.admin()).indices();
        verify(nodeClient.admin().indices()).create(any(), any());
    }
}
