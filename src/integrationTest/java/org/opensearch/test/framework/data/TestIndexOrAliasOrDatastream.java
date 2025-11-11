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

package org.opensearch.test.framework.data;

import java.util.Map;
import java.util.Set;

import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.client.Client;

public interface TestIndexOrAliasOrDatastream {
    String name();

    Set<String> documentIds();

    Map<String, TestData.TestDocument> documents();

    void create(Client client);

    void delete(Client client);

    static void createInitialTestObjects(LocalCluster cluster, TestIndexOrAliasOrDatastream... testIndexLikeArray) {
        try (Client client = cluster.getInternalNodeClient()) {
            for (TestIndexOrAliasOrDatastream testIndexLike : testIndexLikeArray) {
                testIndexLike.create(client);
            }
        }
    }

    static void delete(LocalCluster cluster, TestIndexOrAliasOrDatastream... testIndexLikeArray) {
        try (Client client = cluster.getInternalNodeClient()) {
            for (TestIndexOrAliasOrDatastream testIndexLike : testIndexLikeArray) {
                testIndexLike.delete(client);
            }
        }
    }
}
