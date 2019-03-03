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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.FieldInfos;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.FilterLeafReader;
import org.apache.lucene.index.LeafMetaData;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.PointValues;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.Terms;
import org.apache.lucene.util.Bits;
import org.elasticsearch.index.mapper.MapperService;

import com.google.common.collect.Sets;

class EmptyFilterLeafReader extends FilterLeafReader {
    
    private static final Set<String> metaFields = Sets.union(Sets.newHashSet("_version"), 
            Sets.newHashSet(MapperService.getAllMetaFields()));
    
    private final FieldInfo[] fi;

    EmptyFilterLeafReader(final LeafReader delegate) {
        super(delegate);
        final FieldInfos infos = delegate.getFieldInfos();
        final List<FieldInfo> lfi = new ArrayList<FieldInfo>(metaFields.size());
        for(String metaField: metaFields) {
            final FieldInfo _fi = infos.fieldInfo(metaField);
            if(_fi != null) {
                lfi.add(_fi);
            }
        }
        fi = lfi.toArray(new FieldInfo[0]);
    }

    private static class EmptySubReaderWrapper extends FilterDirectoryReader.SubReaderWrapper {

        @Override
        public LeafReader wrap(final LeafReader reader) {
            return new EmptyFilterLeafReader(reader);
        }

    }

    static class EmptyDirectoryReader extends FilterDirectoryReader {

        public EmptyDirectoryReader(final DirectoryReader in) throws IOException {
            super(in, new EmptySubReaderWrapper());
        }

        @Override
        protected DirectoryReader doWrapDirectoryReader(final DirectoryReader in) throws IOException {
            return new EmptyDirectoryReader(in);
        }
        
        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }
    }

    private boolean isMeta(String field) {
        return metaFields.contains(field);
    }
    
    @Override
    public FieldInfos getFieldInfos() {
        return new FieldInfos(fi);
    }

    @Override
    public NumericDocValues getNumericDocValues(final String field) throws IOException {
        return isMeta(field) ? in.getNumericDocValues(field) : null;
    }

    @Override
    public BinaryDocValues getBinaryDocValues(final String field) throws IOException {
        return isMeta(field) ? in.getBinaryDocValues(field) : null;
    }

    @Override
    public SortedDocValues getSortedDocValues(final String field) throws IOException {
        return isMeta(field) ? in.getSortedDocValues(field) : null;
    }

    @Override
    public SortedNumericDocValues getSortedNumericDocValues(final String field) throws IOException {
        return isMeta(field) ? in.getSortedNumericDocValues(field) : null;
    }

    @Override
    public SortedSetDocValues getSortedSetDocValues(final String field) throws IOException {
        return isMeta(field) ? in.getSortedSetDocValues(field) : null;
    }

    @Override
    public NumericDocValues getNormValues(final String field) throws IOException {
        return isMeta(field) ? in.getNormValues(field) : null;
    }
    
    @Override
    public PointValues getPointValues(String field) throws IOException {
        return isMeta(field) ? in.getPointValues(field) : null;
    }

    @Override
    public Terms terms(String field) throws IOException {
        return isMeta(field) ? in.terms(field) : null;
    }

    @Override
    public LeafMetaData getMetaData() {
        return in.getMetaData();
    }

    @Override
    public Bits getLiveDocs() {
        return new Bits.MatchNoBits(0);
    }

    @Override
    public int numDocs() {
        return 0;
    }

    @Override
    public LeafReader getDelegate() {
        return in;
    }
    
    @Override
    public int maxDoc() {
        return in.maxDoc();
    }

    @Override
    public CacheHelper getCoreCacheHelper() {
        return in.getCoreCacheHelper();
    }

    @Override
    public CacheHelper getReaderCacheHelper() {
        return in.getReaderCacheHelper();
    }
}
