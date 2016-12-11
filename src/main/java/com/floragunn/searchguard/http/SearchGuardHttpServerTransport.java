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

package com.floragunn.searchguard.http;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.http.netty.NettyHttpRequest;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;

public class SearchGuardHttpServerTransport extends SearchGuardSSLNettyHttpServerTransport {

    private final AuditLog auditLog;
    
    @Inject
    public SearchGuardHttpServerTransport(Settings settings, NetworkService networkService, 
            BigArrays bigArrays, SearchGuardKeyStore sgks, AuditLog auditLog, final PrincipalExtractor principalExtractor) {
        super(settings, networkService, bigArrays, sgks, principalExtractor);
        this.auditLog = auditLog;
    }

    @Override
    protected void errorThrown(Throwable t, NettyHttpRequest request) {
        auditLog.logSSLException(request, t, null);
        super.errorThrown(t, request);
    }

    
}
