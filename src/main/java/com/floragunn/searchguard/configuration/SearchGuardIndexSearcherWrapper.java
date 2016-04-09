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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.lucene.document.Document;
import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FieldInfos;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.IndexCommit;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.search.Collector;
import org.apache.lucene.search.CollectorManager;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.Sort;
import org.apache.lucene.search.SortField;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.TopFieldDocs;
import org.apache.lucene.search.Weight;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.Bits;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.engine.EngineConfig;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.engine.IndexSearcherWrapper;
import org.elasticsearch.index.shard.AbstractIndexShardComponent;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.indices.IndicesLifecycle;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.support.Base64Helper;
import com.google.common.base.Strings;
import com.google.common.collect.Iterators;

public class SearchGuardIndexSearcherWrapper extends AbstractIndexShardComponent implements IndexSearcherWrapper {

    private final AdminDNs admindns;

    @Inject
    public SearchGuardIndexSearcherWrapper(final ShardId shardId, final IndicesLifecycle indicesLifecycle, final Settings indexSettings,
            final AdminDNs admindns) {
        super(shardId, indexSettings);
        this.admindns = admindns;
    }

    
    @Override
    public DirectoryReader wrap(final DirectoryReader reader) throws IOException {
        return reader;
    }

    @Override
    public IndexSearcher wrap(final EngineConfig engineConfig, final IndexSearcher searcher) throws EngineException {

        if (!isAdminOrNotRelevant()) {
           return new IndexSearcher(new EmptyReader());
        }

        return searcher;
    }

    private boolean isAdminOrNotRelevant() {
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
    }

}
