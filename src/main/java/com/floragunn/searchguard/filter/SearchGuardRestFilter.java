/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.filter;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.support.HeaderHelper;

public class SearchGuardRestFilter extends RestFilter {

    private final BackendRegistry registry;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    
    @Inject
    public SearchGuardRestFilter(final BackendRegistry registry, AuditLog auditLog, ThreadPool threadPool) {
        super();
        this.registry = registry;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel, final RestFilterChain filterChain) throws Exception {
        
        try {
            HeaderHelper.checkSGHeader(this.threadContext);
        } catch (Exception e) {
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, e));
            return;
        }
        
        if (!registry.authenticate(request, channel, threadContext)) {
            // another roundtrip
            return;
        }
        
        filterChain.continueProcessing(request, channel);
    }

}
