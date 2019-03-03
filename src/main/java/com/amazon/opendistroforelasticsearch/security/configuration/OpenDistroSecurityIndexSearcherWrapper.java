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

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.IndexSearcher;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.shard.IndexSearcherWrapper;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HeaderHelper;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class OpenDistroSecurityIndexSearcherWrapper extends IndexSearcherWrapper {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final ThreadContext threadContext;
    protected final Index index;
    protected final String opendistrosecurityIndex;
    private final AdminDNs adminDns;

    //constructor is called per index, so avoid costly operations here
	public OpenDistroSecurityIndexSearcherWrapper(final IndexService indexService, final Settings settings, final AdminDNs adminDNs) {
	    index = indexService.index();
	    threadContext = indexService.getThreadPool().getThreadContext();
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.adminDns = adminDNs;
	}

    @Override
    public final DirectoryReader wrap(final DirectoryReader reader) throws IOException {

        if (isSecurityIndexRequest() && !isAdminAuthenticatedOrInternalRequest()) {
            return new EmptyFilterLeafReader.EmptyDirectoryReader(reader);
        }


        return dlsFlsWrap(reader, isAdminAuthenticatedOrInternalRequest());
    }

    @Override
    public final IndexSearcher wrap(final IndexSearcher searcher) throws EngineException {
        return dlsFlsWrap(searcher, isAdminAuthenticatedOrInternalRequest());
    }

    protected IndexSearcher dlsFlsWrap(final IndexSearcher searcher, boolean isAdmin) throws EngineException {
        return searcher;
    }

    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader, boolean isAdmin) throws IOException {
        return reader;
    }

    protected final boolean isAdminAuthenticatedOrInternalRequest() {

        final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        if (user != null && adminDns.isAdmin(user)) {
            return true;
        }

        if ("true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER))) {
            return true;
        }

        return false;
    }

    protected final boolean isSecurityIndexRequest() {
        return index.getName().equals(opendistrosecurityIndex);
    }
}
