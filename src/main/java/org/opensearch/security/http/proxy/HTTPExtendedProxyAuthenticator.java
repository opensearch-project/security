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

package org.opensearch.security.http.proxy;

import java.nio.file.Path;
import java.util.List;
import java.util.Map.Entry;

import com.google.common.base.Joiner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.http.HTTPProxyAuthenticator;
import org.opensearch.security.user.AuthCredentials;

public class HTTPExtendedProxyAuthenticator extends HTTPProxyAuthenticator{

    private static final String ATTR_PROXY = "attr.proxy.";
    private static final String ATTR_PROXY_USERNAME = "attr.proxy.username";
    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile Settings settings;

    public HTTPExtendedProxyAuthenticator(Settings settings, final Path configPath) {
        super(settings, configPath);
        this.settings = settings;
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, ThreadContext context) {
    	AuthCredentials credentials = super.extractCredentials(request, context);
    	if(credentials == null) {
    	    return null;
    	}
        
        String attrHeaderPrefix = settings.get("attr_header_prefix");
        if(Strings.isNullOrEmpty(attrHeaderPrefix)) {
            log.debug("attr_header_prefix is null. Skipping additional attribute extraction");
            return credentials;
        } else if(log.isDebugEnabled()) {
            log.debug("attrHeaderPrefix {}", attrHeaderPrefix);
        }
        
        credentials.addAttribute(ATTR_PROXY_USERNAME, credentials.getUsername());
        attrHeaderPrefix = attrHeaderPrefix.toLowerCase();
        for (Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
            String key = entry.getKey().toLowerCase();
            if(key.startsWith(attrHeaderPrefix)) {
                key = ATTR_PROXY + key.substring(attrHeaderPrefix.length());
                credentials.addAttribute(key, Joiner.on(",").join(entry.getValue().iterator()));
                if(log.isTraceEnabled()) {
                    log.trace("Found user custom attribute '{}'", key);
                }
            }
        }
        return credentials.markComplete();
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "extended-proxy";
    }
}
