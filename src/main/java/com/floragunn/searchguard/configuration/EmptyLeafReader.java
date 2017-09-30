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
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;

class EmptyLeafReader extends LeafReader {
    
    private final static Bits liveDocs = new Bits.MatchNoBits(0);
    private final LeafReader lr;

    public EmptyLeafReader(LeafReader lr) {
        super();
        this.lr = lr;
        tryIncRef();
    }

    @Override
    public NumericDocValues getNumericDocValues(final String field) throws IOException {
        return new NumericDocValues() {

            @Override
            public long longValue() throws IOException {
                return 0;
            }

            @Override
            public boolean advanceExact(int target) throws IOException {
                return false;
            }

            @Override
            public int docID() {
                return 0;
            }

            @Override
            public int nextDoc() throws IOException {
                return 0;
            }

            @Override
            public int advance(int target) throws IOException {
                return 0;
            }

            @Override
            public long cost() {
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
        return lr.getCoreCacheHelper();
    }

    @Override
    public Terms terms(String field) throws IOException {
        //if("_id".equals(field)) {
            return new Terms() {
                
                @Override
                public long size() throws IOException {
                    return 0;
                }
                
                @Override
                public TermsEnum iterator() throws IOException {
                    
                    return new TermsEnum() {

                        @Override
                        public BytesRef next() throws IOException {
                            return null;
                        }

                        @Override
                        public SeekStatus seekCeil(BytesRef text) throws IOException {
                            return null;
                        }

                        @Override
                        public void seekExact(long ord) throws IOException {                            
                        }

                        @Override
                        public BytesRef term() throws IOException {
                            return null;
                        }

                        @Override
                        public long ord() throws IOException {
                            return 0;
                        }

                        @Override
                        public int docFreq() throws IOException {
                            return 0;
                        }

                        @Override
                        public long totalTermFreq() throws IOException {
                            return 0;
                        }

                        @Override
                        public PostingsEnum postings(PostingsEnum reuse, int flags) throws IOException {
                            return null;
                        }

                    };
                }
                
                @Override
                public boolean hasPositions() {
                    return false;
                }
                
                @Override
                public boolean hasPayloads() {
                    return false;
                }
                
                @Override
                public boolean hasOffsets() {
                    return false;
                }
                
                @Override
                public boolean hasFreqs() {
                    return false;
                }
                
                @Override
                public long getSumTotalTermFreq() throws IOException {
                    return 0;
                }
                
                @Override
                public long getSumDocFreq() throws IOException {
                    return 0;
                }
                
                @Override
                public int getDocCount() throws IOException {
                    return 0;
                }
            };
        //}
        
        //return null;
    }

    @Override
    public PointValues getPointValues(String field) throws IOException {
        return null;
    }

    @Override
    public LeafMetaData getMetaData() {
        return null;
    }

    @Override
    public CacheHelper getReaderCacheHelper() {
        return lr.getReaderCacheHelper();
    }
}
