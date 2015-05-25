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

package com.floragunn.searchguard.rest;

import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.audit.AuditListener;
import com.floragunn.searchguard.service.SearchGuardService;

public class DefaultRestFilter extends AbstractACRestFilter {

    public DefaultRestFilter(final SearchGuardService service, final String filterType, final String filterName,
            final AuditListener auditListener) {
        super(service, filterType, filterName, auditListener);
    }

    @Override
    public void processSecure(final RestRequest request, final RestChannel channel, final RestFilterChain filterChain) throws Exception {

        filterChain.continueProcessing(request, channel);

    }
}
