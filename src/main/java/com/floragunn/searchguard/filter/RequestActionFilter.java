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

package com.floragunn.searchguard.filter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.util.ConfigConstants;

public class RequestActionFilter extends AbstractActionFilter {

    private final String filterType = "actionrequestfilter";
    private final Map<String, Tuple<List<String>, List<String>>> filterMap = new HashMap<String, Tuple<List<String>, List<String>>>();

    @Inject
    public RequestActionFilter(final Settings settings, final AuthenticationBackend backend, final Authorizator authorizator,
            final ClusterService clusterService) {
        super(settings, backend, authorizator, clusterService);

        final String[] arFilters = settings.getAsArray(ConfigConstants.SEARCHGUARD_ACTIONREQUESTFILTER);
        for (int i = 0; i < arFilters.length; i++) {
            final String filterName = arFilters[i];

            final List<String> allowedActions = Arrays.asList(settings.getAsArray("searchguard." + filterType + "." + filterName
                    + ".allowed_actions", new String[0]));
            final List<String> forbiddenActions = Arrays.asList(settings.getAsArray("searchguard." + filterType + "." + filterName
                    + ".forbidden_actions", new String[0]));

            filterMap.put(filterName, new Tuple<List<String>, List<String>>(allowedActions, forbiddenActions));
        }

    }

    @Override
    public void applySecure(final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (filterMap.size() == 0) {
            chain.proceed(action, request, listener);
            return;
        }

        for (final Iterator<Entry<String, Tuple<List<String>, List<String>>>> it = filterMap.entrySet().iterator(); it.hasNext();) {

            final Entry<String, Tuple<List<String>, List<String>>> entry = it.next();

            final String filterName = entry.getKey();
            final List<String> allowedActions = entry.getValue().v1();
            final List<String> forbiddenActions = entry.getValue().v2();

            request.putInContext("searchguard." + filterType + "." + filterName + ".allowed_actions", allowedActions);
            request.putInContext("searchguard." + filterType + "." + filterName + ".forbidden_actions", forbiddenActions);

            if (request.hasInContext("searchguard_filter") && filterType != null) {
                if (!((List<String>) request.getFromContext("searchguard_filter")).contains(filterType + ":" + filterName)) {
                    ((List<String>) request.getFromContext("searchguard_filter")).add(filterType + ":" + filterName);
                }
            } else if (filterType != null) {
                final List<String> _filters = new ArrayList<String>();
                _filters.add(filterType + ":" + filterName);
                request.putInContext("searchguard_filter", _filters);
            }
        }

        chain.proceed(action, request, listener);
    }

}
