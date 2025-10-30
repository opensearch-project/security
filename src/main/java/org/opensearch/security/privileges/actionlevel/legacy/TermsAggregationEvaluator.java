/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.privileges.actionlevel.legacy;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Streams;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesAction;
import org.opensearch.action.get.GetAction;
import org.opensearch.action.get.MultiGetAction;
import org.opensearch.action.search.MultiSearchAction;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.index.query.MatchNoneQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;

public class TermsAggregationEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final ImmutableSet<String> READ_ACTIONS = ImmutableSet.of(
        MultiSearchAction.NAME,
        MultiGetAction.NAME,
        GetAction.NAME,
        SearchAction.NAME,
        FieldCapabilitiesAction.NAME
    );

    private static final QueryBuilder NONE_QUERY = new MatchNoneQueryBuilder();

    public TermsAggregationEvaluator() {}

    public PrivilegesEvaluatorResponse evaluate(
        OptionallyResolvedIndices optionallyResolvedIndices,
        ActionRequest request,
        PrivilegesEvaluationContext context,
        ActionPrivileges actionPrivileges
    ) {
        // This is only applicable for SearchRequests and for present ResolvedIndices information (for SearchRequests that is usually the
        // case)
        if (!(request instanceof SearchRequest sr) || !(optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices)) {
            return null;
        }

        try {

            if (sr.source() != null
                && sr.source().query() == null
                && sr.source().aggregations() != null
                && sr.source().aggregations().getAggregatorFactories() != null
                && sr.source().aggregations().getAggregatorFactories().size() == 1
                && sr.source().size() == 0) {
                AggregationBuilder ab = sr.source().aggregations().getAggregatorFactories().iterator().next();
                if (ab instanceof TermsAggregationBuilder && "terms".equals(ab.getType()) && "indices".equals(ab.getName())) {
                    if ("_index".equals(((TermsAggregationBuilder) ab).field())
                        && ab.getPipelineAggregations().isEmpty()
                        && ab.getSubAggregations().isEmpty()) {

                        PrivilegesEvaluatorResponse subResponse = actionPrivileges.hasIndexPrivilege(
                            context,
                            READ_ACTIONS,
                            ResolvedIndices.unknown()
                        );

                        if (subResponse.isPartiallyOk()) {
                            sr.source()
                                .query(
                                    new TermsQueryBuilder(
                                        "_index",
                                        Streams.concat(
                                            subResponse.getAvailableIndices().stream(),
                                            resolvedIndices.remote().asRawExpressions().stream()
                                        ).toArray(String[]::new)
                                    )
                                );
                        } else if (!subResponse.isAllowed()) {
                            sr.source().query(NONE_QUERY);
                        }

                        return PrivilegesEvaluatorResponse.ok();
                    }
                }
            }

        } catch (Exception e) {
            log.warn("Unable to evaluate terms aggregation", e);
        }

        return null;
    }
}
