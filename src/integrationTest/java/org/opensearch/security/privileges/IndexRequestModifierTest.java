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

package org.opensearch.security.privileges;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.OriginalIndices;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.util.MockIndexMetadataBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        IndexRequestModifierTest.SetLocalIndicesToEmpty.class })
public class IndexRequestModifierTest {

    static final IndexNameExpressionResolver indexNameExpressionResolver = new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY));
    static final Metadata metadata = MockIndexMetadataBuilder.indices("index").build();
    final static ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(metadata).build();

    @RunWith(Parameterized.class)
    public static class SetLocalIndicesToEmpty {


        String description;
        IndicesRequest request;

        @Test
        public void setLocalIndicesToEmpty() {

            ResolvedIndices resolvedIndices = ResolvedIndices.of("index");

            if (Arrays.asList(request.indices()).contains("remote:index")) {
                resolvedIndices = resolvedIndices.withRemoteIndices(Map.of("remote", new OriginalIndices(new String [] {"index"}, request.indicesOptions())));
            }

            boolean success = new IndicesRequestModifier().setLocalIndicesToEmpty((ActionRequest) request, resolvedIndices);

            if (!(request instanceof IndicesRequest.Replaceable)) {
                assertFalse(success);
            } else
            if (!request.indicesOptions().allowNoIndices()) {
                assertFalse(success);
            } else {
                assertTrue(success);

                String [] finalResolvedIndices = indexNameExpressionResolver.concreteIndexNames(clusterState, request);

                    assertEquals("Resolved to empty indices: " + Arrays.asList(finalResolvedIndices), 0, finalResolvedIndices.length);
            }
        }


        @Parameterized.Parameters(name = "{0}")
        public static Collection<Object[]> params() {
            return Arrays.asList(
                    new Object [] {
                            "lenient expand open", new SearchRequest("index").indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN)
                    },
                    new Object [] {
                            "lenient expand open/closed", new SearchRequest("index").indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED)
                    },
                    new Object [] {
                            "lenient expand open/closed/hidden", new SearchRequest("index").indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED_HIDDEN)
                    },
                    new Object [] {
                           "allow no indices", new SearchRequest("index").indicesOptions(IndicesOptions.fromOptions(false, true, false, false))
                    },
                    new Object [] {
                         "ignore unavailable",   new SearchRequest("index").indicesOptions(IndicesOptions.fromOptions(true, false, false, false))
                    },
                    new Object [] {
                          "strict single index",  new SearchRequest("index").indicesOptions(IndicesOptions.STRICT_SINGLE_INDEX_NO_EXPAND_FORBID_CLOSED)
                    },
                    new Object [] {
                        "with remote index",    new SearchRequest("index", "remote:index").indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN)
                    },
                    new Object [] {
                            "not implementing IndicesRequest.Replaceable",    new IndexRequest("index")
                    }
            );

        }

        public SetLocalIndicesToEmpty(String description, IndicesRequest request) {
            this.description = description;
            this.request = request;
        }
    }
}
