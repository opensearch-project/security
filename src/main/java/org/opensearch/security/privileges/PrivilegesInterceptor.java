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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.privileges;

import java.util.Map;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.user.User;

public class PrivilegesInterceptor {

    public static class ReplaceResult {
        final boolean continueEvaluation;
        final boolean accessDenied;
        final CreateIndexRequestBuilder createIndexRequestBuilder;

        private ReplaceResult(boolean continueEvaluation, boolean accessDenied, CreateIndexRequestBuilder createIndexRequestBuilder) {
            this.continueEvaluation = continueEvaluation;
            this.accessDenied = accessDenied;
            this.createIndexRequestBuilder = createIndexRequestBuilder;
        }
    }

    public static final ReplaceResult CONTINUE_EVALUATION_REPLACE_RESULT = new ReplaceResult(true, false, null);
    public static final ReplaceResult ACCESS_DENIED_REPLACE_RESULT = new ReplaceResult(false, true, null);
    public static final ReplaceResult ACCESS_GRANTED_REPLACE_RESULT = new ReplaceResult(false, false, null);
    protected static ReplaceResult newAccessGrantedReplaceResult(CreateIndexRequestBuilder createIndexRequestBuilder) {
        return new ReplaceResult(false, false, createIndexRequestBuilder);
    }

    protected final IndexNameExpressionResolver resolver;
    protected final ClusterService clusterService;
    protected final Client client;
    protected final ThreadPool threadPool;

    public PrivilegesInterceptor(final IndexNameExpressionResolver resolver, final ClusterService clusterService, 
            final Client client, ThreadPool threadPool) {
        this.resolver = resolver;
        this.clusterService = clusterService;
        this.client = client;
        this.threadPool = threadPool;
    }

    public ReplaceResult replaceDashboardsIndex(final ActionRequest request, final String action, final User user, final DynamicConfigModel config,
                                                final Resolved requestedResolved, final Map<String, Boolean> tenants) {
        throw new RuntimeException("not implemented");
    }
    
    protected final ThreadContext getThreadContext() {
        return threadPool.getThreadContext();
    }
}
