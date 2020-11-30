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

import java.util.Map;
import java.util.Set;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.search.query.QuerySearchResult;
import org.elasticsearch.threadpool.ThreadPool;

public interface DlsFlsRequestValve {
    
    /**
     * SSLConfigConstants.java
     * @param request
     * @param listener
     * @return false to stop
     */
    boolean invoke(ActionRequest request, ActionListener<?> listener, Map<String,Set<String>> allowedFlsFields, final Map<String,Set<String>> maskedFields, Map<String,Set<String>> queries);

    void handleSearchContext(SearchContext context, ThreadPool threadPool, NamedXContentRegistry namedXContentRegistry);

    void onQueryPhase(QuerySearchResult queryResult);
    
    public static class NoopDlsFlsRequestValve implements DlsFlsRequestValve {

        @Override
        public boolean invoke(ActionRequest request, ActionListener<?> listener, Map<String,Set<String>> allowedFlsFields, final Map<String,Set<String>> maskedFields, Map<String,Set<String>> queries) {
            return true;
        }

        @Override
        public void handleSearchContext(SearchContext context, ThreadPool threadPool, NamedXContentRegistry namedXContentRegistry) {

        }

        @Override
        public void onQueryPhase(QuerySearchResult queryResult) {

        }
    }
    
}
