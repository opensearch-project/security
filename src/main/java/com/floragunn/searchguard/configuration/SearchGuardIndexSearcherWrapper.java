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

package com.floragunn.searchguard.configuration;

import java.io.IOException;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.IndexSearcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.index.shard.ShardUtils;

import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;

public class SearchGuardIndexSearcherWrapper extends IndexSearcherWrapper {

    protected final Logger log = LogManager.getLogger(this.getClass());
	private final ThreadContext threadContext;
	private final Index index;
	private final String searchguardIndex;
	
	public SearchGuardIndexSearcherWrapper(final IndexService indexService, Settings settings) {
	    index = indexService.index();
	    threadContext = indexService.getThreadPool().getThreadContext();
        this.searchguardIndex = settings.get(ConfigConstants.SG_CONFIG_INDEX, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
	}

    @Override
    public final DirectoryReader wrap(final DirectoryReader reader) throws IOException {

        //if (log.isTraceEnabled()) {
        //    log.trace("DirectoryReader {} should be wrapped", reader.getClass());
        //}
        
        if (!isAdminAuthenticatedOrInternalRequest()) {

            //if (settings == null || settings.getAsBoolean("searchguard.dynamic.dlsfls_enabled", true)) {
                return dlsFlsWrap(reader);
            //}
        }

        return reader;

    }

    @Override
    public final IndexSearcher wrap(final IndexSearcher searcher) throws EngineException {

    	//if (log.isTraceEnabled()) {
        //    log.trace("IndexSearcher {} should be wrapped (reader is {})", searcher.getClass(), searcher.getIndexReader().getClass());
        //}
        
        if (isSearchGuardIndexRequest() && !isAdminAuthenticatedOrInternalRequest()) {
            return new IndexSearcher(new EmptyReader());
        }

        if (!isAdminAuthenticatedOrInternalRequest()) {

            //if (settings == null || settings.getAsBoolean("searchguard.dynamic.dlsfls_enabled", true)) {
                return dlsFlsWrap(searcher);
            //}
        }

        return searcher;
    }

    protected IndexSearcher dlsFlsWrap(final IndexSearcher searcher) throws EngineException {
        return searcher;
    }

    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader) throws IOException {
        return reader;
    }

    protected final boolean isAdminAuthenticatedOrInternalRequest() {
    	 
        final User user = (User) threadContext.getTransient(ConfigConstants.SG_USER);
        
        //System.out.println("5>>>>> user: "+user+" is admin "+(user==null?false:AdminDNs.isAdmin(user.getName())));
               
        if (user != null && AdminDNs.isAdmin(user.getName())) { //TODO static hack
            return true;
        }
        
        if ("true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.SG_CONF_REQUEST_HEADER))) {
            return true;
        }

        return false;
    }

    protected final boolean isSearchGuardIndexRequest() {
        return index.getName().equals(searchguardIndex);

    }
}
