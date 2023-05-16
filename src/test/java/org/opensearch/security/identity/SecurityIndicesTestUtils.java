package org.opensearch.security.identity;

import org.mockito.quality.Strictness;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.Metadata;

import java.util.Arrays;
import java.util.TreeMap;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

public class SecurityIndicesTestUtils {
    public static ClusterState createClusterState(final IndexShorthand... indices) {
        final TreeMap<String, IndexAbstraction> indexMap = new TreeMap<String, IndexAbstraction>();
        Arrays.stream(indices).forEach(indexShorthand -> {
            final IndexAbstraction indexAbstraction = mock(IndexAbstraction.class, withSettings().strictness(Strictness.LENIENT));
            when(indexAbstraction.getType()).thenReturn(indexShorthand.type);
            indexMap.put(indexShorthand.name, indexAbstraction);
        });

        final Metadata mockMetadata = mock(Metadata.class, withSettings().strictness(Strictness.LENIENT));
        when(mockMetadata.getIndicesLookup()).thenReturn(indexMap);

        final ClusterState mockClusterState = mock(ClusterState.class, withSettings().strictness(Strictness.LENIENT));
        when(mockClusterState.getMetadata()).thenReturn(mockMetadata);
        when(mockClusterState.metadata()).thenReturn(mockMetadata);

        if (indices != null) {
            for (IndexShorthand index : indices) {
                when(mockMetadata.hasConcreteIndex(index.name)).thenReturn(true);
            }
        }

        return mockClusterState;
    }

    public static Client createNodeClient() {
        final IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class, withSettings().strictness(Strictness.LENIENT));

        final AdminClient mockAdminClient = mock(AdminClient.class, withSettings().strictness(Strictness.LENIENT));
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);

        final Client mockClient = mock(Client.class, withSettings().strictness(Strictness.LENIENT));
        when(mockClient.admin()).thenReturn(mockAdminClient);

        return mockClient;
    }

    public static class IndexShorthand {
        public final String name;
        public final IndexAbstraction.Type type;
        public IndexShorthand(final String name, final IndexAbstraction.Type type) {
            this.name = name;
            this.type = type;
        }
    }
}
