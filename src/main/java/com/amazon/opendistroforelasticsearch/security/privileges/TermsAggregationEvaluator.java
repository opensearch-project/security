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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.index.query.MatchNoneQueryBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.TermsQueryBuilder;
import org.elasticsearch.search.aggregations.AggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.terms.TermsAggregationBuilder;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.securityconf.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class TermsAggregationEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final String[] READ_ACTIONS = new String[]{
            "indices:data/read/msearch",
            "indices:data/read/mget",
            "indices:data/read/get",
            "indices:data/read/search",
            "indices:data/read/field_caps*"
            //"indices:admin/mappings/fields/get*"
            };
    
    private static final QueryBuilder NONE_QUERY = new MatchNoneQueryBuilder();
    
    public TermsAggregationEvaluator() {
    }
    
    public PrivilegesEvaluatorResponse evaluate(final Resolved resolved, final ActionRequest request, ClusterService clusterService, User user, SecurityRoles securityRoles,  IndexNameExpressionResolver resolver, PrivilegesEvaluatorResponse presponse) {
        try {
            if(request instanceof SearchRequest) {
                SearchRequest sr = (SearchRequest) request;

                if(     sr.source() != null
                        && sr.source().query() == null
                        && sr.source().aggregations() != null
                        && sr.source().aggregations().getAggregatorFactories() != null
                        && sr.source().aggregations().getAggregatorFactories().size() == 1
                        && sr.source().size() == 0) {
                   AggregationBuilder ab = sr.source().aggregations().getAggregatorFactories().iterator().next();
                   if(     ab instanceof TermsAggregationBuilder
                           && "terms".equals(ab.getType())
                           && "indices".equals(ab.getName())) {
                       if("_index".equals(((TermsAggregationBuilder) ab).field())
                               && ab.getPipelineAggregations().isEmpty()
                               && ab.getSubAggregations().isEmpty()) {

                           
                           final Set<String> allPermittedIndices = securityRoles.getAllPermittedIndicesForKibana(resolved, user, READ_ACTIONS, resolver, clusterService);
                           if(allPermittedIndices == null || allPermittedIndices.isEmpty()) {
                               sr.source().query(NONE_QUERY);
                           } else {
                               sr.source().query(new TermsQueryBuilder("_index", allPermittedIndices));
                           }                 
                           
                           presponse.allowed = true;
                           return presponse.markComplete();
                       }
                   }
                }
            }
        } catch (Exception e) {
            log.warn("Unable to evaluate terms aggregation",e);
            return presponse;
        }
        
        return presponse;
    }
}
