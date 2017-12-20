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

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.LeafReader;
import org.elasticsearch.common.lucene.index.ElasticsearchLeafReader;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.shard.ShardId;

public class EmptyDirectoryReader extends FilterDirectoryReader {

    private final Index index;

    private static class EmptySubReaderWrapper extends SubReaderWrapper {

        private final Index index;

        public EmptySubReaderWrapper(final Index index) {
            this.index = index;
        }

        @Override
        public LeafReader wrap(final LeafReader reader) {
            return new ElasticsearchLeafReader(new EmptyLeafReader(reader), new ShardId(index, 0));
        }
    }

    EmptyDirectoryReader(final DirectoryReader in, final Index index) throws IOException {
        super(in, new EmptySubReaderWrapper(index));
        this.index = index;
    }

    @Override
    protected DirectoryReader doWrapDirectoryReader(final DirectoryReader in) throws IOException {
        return new EmptyDirectoryReader(in, index);
    }

    @Override
    public CacheHelper getReaderCacheHelper() {
        return in.getReaderCacheHelper();
    }

    @Override
    public String toString() {
        return "EmptyDirectoryReader(" + in.toString() + ")";
    }
}
