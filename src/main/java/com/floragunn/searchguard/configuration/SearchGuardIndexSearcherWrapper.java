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
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.engine.EngineConfig;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.engine.IndexSearcherWrapper;
import org.elasticsearch.index.shard.AbstractIndexShardComponent;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.indices.IndicesLifecycle;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;

public class SearchGuardIndexSearcherWrapper extends AbstractIndexShardComponent implements IndexSearcherWrapper, ConfigChangeListener {

    private final AdminDNs admindns;
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private volatile Settings settings;

    // {
    // System.out.println("CREATE INSTANCE SearchGuardIndexSearcherWrapper--//"+Thread.currentThread().getName()+"#"+this.hashCode());
    // }

    @Inject
    public SearchGuardIndexSearcherWrapper(final ShardId shardId, final IndicesLifecycle indicesLifecycle, final Settings indexSettings,
            final AdminDNs admindns, final TransportConfigUpdateAction tcua) {
        super(shardId, indexSettings);
        this.admindns = admindns;
        tcua.addConfigChangeListener("config", this);
    }

    @Override
    public final DirectoryReader wrap(final DirectoryReader reader) throws IOException {

        if (log.isTraceEnabled()) {
            log.trace("DirectoryReader {} should be wrapped", reader.getClass());
        }

        if (!isAdminAuhtenticatedOrInternalReqest()) {

            if (settings == null || settings.getAsBoolean("searchguard.dynamic.dlsfls_enabled", true)) {
                return dlsFlsWrap(reader);
            }
        }

        return reader;

    }

    @Override
    public final IndexSearcher wrap(final EngineConfig engineConfig, final IndexSearcher searcher) throws EngineException {

        if (log.isTraceEnabled()) {
            log.trace("IndexSearcher {} should be wrapped (reader is {})", searcher.getClass(), searcher.getIndexReader().getClass());
        }

        if (isSearchGuardIndexRequest() && !isAdminAuhtenticatedOrInternalReqest()) {
            return new IndexSearcher(new EmptyReader());
        }

        if (!isAdminAuhtenticatedOrInternalReqest()) {

            if (settings == null || settings.getAsBoolean("searchguard.dynamic.dlsfls_enabled", true)) {
                return dlsFlsWrap(engineConfig, searcher);
            }
        }

        return searcher;
    }

    protected IndexSearcher dlsFlsWrap(final EngineConfig engineConfig, final IndexSearcher searcher) throws EngineException {
        return searcher;
    }

    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader) throws IOException {
        return reader;
    }

    protected final boolean isAdminAuhtenticatedOrInternalReqest() {
        final RequestHolder current = RequestHolder.current();

        if (current != null) {
            final TransportRequest request = current.getRequest();

            if (request != null) {
                if (request.getFromContext("_sg_internal_request") == Boolean.TRUE) {
                    return true;
                }

                final String transportPrincipal = (String) request.getFromContext("_sg_ssl_transport_principal");

                if (transportPrincipal != null && admindns.isAdmin(transportPrincipal)) {
                    return true;
                }

                if (request.getFromContext("_sg_ssl_transport_intercluster_request") == Boolean.TRUE) {

                    if (request.hasHeader("_sg_internal_request")) {
                        return true;
                    }

                }
            }
        }

        return false;
    }

    protected final boolean isSearchGuardIndexRequest() {
        return shardId.index().getName().equals("searchguard");
    }

    @Override
    public void onChange(final String event, final Settings settings) {
        // System.out.println("UPDATE SETT SearchGuardIndexSearcherWrapper--//"+Thread.currentThread().getName()+"#"+this.hashCode());
        this.settings = settings;
    }

    @Override
    public void validate(final String event, final Settings settings) throws ElasticsearchSecurityException {
        // TODO Auto-generated method stub

    }

    @Override
    public boolean isInitialized() {
        return this.settings != null;
    }

    /*protected boolean isAdminOrNotRelevant() {
        if (shardId.index().getName().equals("searchguard")) {
            final RequestHolder current = RequestHolder.current();

            if (current != null) {
                final TransportRequest request = current.getRequest();

                if (request != null) {
                    if (request.getFromContext("_sg_internal_request") == Boolean.TRUE) {
                        return true;
                    }

                    final String transportPrincipal = (String) request.getFromContext("_sg_ssl_transport_principal");

                    if (transportPrincipal != null && admindns.isAdmin(transportPrincipal)) {
                        return true;
                    }

                    if (request.getFromContext("_sg_ssl_transport_intercluster_request") == Boolean.TRUE) {

                        if (request.hasHeader("_sg_internal_request")) {
                            return true;
                        }

                    }
                } else {
                    return false;
                }

            } else {
                return false;
            }

            return false;
        }

        return true;
    }*/

}
