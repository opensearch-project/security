/*
 * Copyright 2015-2017 floragunn Gmbh
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

import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.FieldInfos;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.LeafMetaData;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.PointValues;
import org.apache.lucene.index.PostingsEnum;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.search.Sort;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;

class EmptyReader extends LeafReader {
    
    //private final Object coreCacheKey;
    
    public EmptyReader(final Object coreCacheKey) {
        super();
        //this.coreCacheKey = coreCacheKey;
        tryIncRef();
    }

    @Override
    public NumericDocValues getNumericDocValues(final String field) throws IOException {
        return new NumericDocValues() {

            @Override
            public long longValue() throws IOException {
                // TODO Auto-generated method stub
                return 0;
            }

            @Override
            public boolean advanceExact(int target) throws IOException {
                // TODO Auto-generated method stub
                return false;
            }

            @Override
            public int docID() {
                // TODO Auto-generated method stub
                return 0;
            }

            @Override
            public int nextDoc() throws IOException {
                // TODO Auto-generated method stub
                return 0;
            }

            @Override
            public int advance(int target) throws IOException {
                // TODO Auto-generated method stub
                return 0;
            }

            @Override
            public long cost() {
                // TODO Auto-generated method stub
                return 0;
            }
        };
    }

    @Override
    public BinaryDocValues getBinaryDocValues(final String field) throws IOException {
        return null;
    }

    @Override
    public SortedDocValues getSortedDocValues(final String field) throws IOException {
        return null;
    }

    @Override
    public SortedNumericDocValues getSortedNumericDocValues(final String field) throws IOException {
        return null;
    }

    @Override
    public SortedSetDocValues getSortedSetDocValues(final String field) throws IOException {
        return null;
    }

    @Override
    public NumericDocValues getNormValues(final String field) throws IOException {
        return null;
    }
    
    @Override
    public FieldInfos getFieldInfos() {
        return new FieldInfos(new FieldInfo[0]);
    }

    final Bits liveDocs = new Bits.MatchNoBits(0);

    @Override
    public Bits getLiveDocs() {
        return liveDocs;
    }

    @Override
    public void checkIntegrity() throws IOException {
    }

    @Override
    public Fields getTermVectors(final int docID) throws IOException {
        return null;
    }

    @Override
    public int numDocs() {
        return 0;
    }

    @Override
    public int maxDoc() {
        return 0;
    }

    @Override
    public void document(final int docID, final StoredFieldVisitor visitor) throws IOException {
    }

    @Override
    protected void doClose() throws IOException {
    }

    @Override
    public boolean hasDeletions() {
        return false;
    }

    @Override
    public CacheHelper getCoreCacheHelper() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Terms terms(String field) throws IOException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public PointValues getPointValues(String field) throws IOException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public LeafMetaData getMetaData() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public CacheHelper getReaderCacheHelper() {
        // TODO Auto-generated method stub
        return null;
    }
}
