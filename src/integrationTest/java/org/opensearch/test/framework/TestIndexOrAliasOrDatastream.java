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

package org.opensearch.test.framework;

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

    default TestIndexOrAliasOrDatastream intersection(TestIndexOrAliasOrDatastream other) {
        if (other == this) {
            return this;
        }

        if (!this.name().equals(other.name())) {
            throw new IllegalArgumentException("Cannot intersect different indices: " + this + " vs " + other);
        }

        return this;
    }

    static void createInitialTestObjects(LocalCluster cluster, TestIndexOrAliasOrDatastream... testIndexOrAliasOrDatastreamArray) {
        try (Client client = cluster.getInternalNodeClient()) {
            for (TestIndexOrAliasOrDatastream testIndexOrAliasOrDatastream : testIndexOrAliasOrDatastreamArray) {
                testIndexOrAliasOrDatastream.create(client);
            }
        }
    }

    static void delete(LocalCluster cluster, TestIndexOrAliasOrDatastream... testIndexOrAliasOrDatastreamArray) {
        try (Client client = cluster.getInternalNodeClient()) {
            for (TestIndexOrAliasOrDatastream testIndexOrAliasOrDatastream : testIndexOrAliasOrDatastreamArray) {
                testIndexOrAliasOrDatastream.delete(client);
            }
        }
    }
}
