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

package org.opensearch.security.configuration;

import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.query.QuerySearchResult;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.EvaluatedDlsFlsConfig;
import org.opensearch.threadpool.ThreadPool;

public interface DlsFlsRequestValve {

    boolean invoke(
        String action,
        ActionRequest request,
        ActionListener<?> listener,
        EvaluatedDlsFlsConfig evaluatedDlsFlsConfig,
        Resolved resolved
    );

    void handleSearchContext(SearchContext context, ThreadPool threadPool, NamedXContentRegistry namedXContentRegistry);

    void onQueryPhase(QuerySearchResult queryResult);

    public static class NoopDlsFlsRequestValve implements DlsFlsRequestValve {

        @Override
        public boolean invoke(
            String action,
            ActionRequest request,
            ActionListener<?> listener,
            EvaluatedDlsFlsConfig evaluatedDlsFlsConfig,
            Resolved resolved
        ) {
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
