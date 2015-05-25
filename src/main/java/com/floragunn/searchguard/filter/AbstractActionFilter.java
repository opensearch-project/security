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

import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.MultiSearchResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.support.DelegatingActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.query.IdsQueryBuilder;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.service.SearchGuardService;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public abstract class AbstractActionFilter implements ActionFilter {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    protected final Settings settings;
    protected final AuthenticationBackend backend;
    protected final Authorizator authorizator;
    protected final ClusterService clusterService;

    @Override
    public final int order() {
        return Integer.MIN_VALUE;
    }

    protected AbstractActionFilter(final Settings settings, final AuthenticationBackend backend, final Authorizator authorizator,
            final ClusterService clusterService) {
        this.settings = settings;
        this.authorizator = authorizator;
        this.backend = backend;
        this.clusterService = clusterService;

    }

    @Override
    public final void apply(final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        log.debug("REQUEST on node {}: {} ({}) from {}", clusterService.localNode().getName(), action, request.getClass(),
                request.remoteAddress() == null ? "INTRANODE" : request.remoteAddress().toString());
        log.debug("Context {}", request.getContext());
        log.debug("Headers {}", request.getHeaders());

        if (action.startsWith("cluster:monitor/")) {
            chain.proceed(action, request, listener);
            return;
        }

        final User restUser = request.getFromContext("searchguard_authenticated_user", null);

        final boolean restAuthenticated = restUser != null;

        if (restAuthenticated) {
            log.debug("TYPE: rest authenticated request, apply filters");
            applySecure(action, request, listener, chain);
            return;
        }

        final boolean intraNodeRequest = request.remoteAddress() == null;

        if (intraNodeRequest) {
            log.debug("TYPE: intra node request, skip filters");
            chain.proceed(action, request, listener);
            return;
        }

        final Object authHeader = request.getHeader("searchguard_authenticated_transport_request");
        boolean interNodeAuthenticated = false;

        if (authHeader != null && authHeader instanceof String) {
            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, SearchGuardService.getSecretKey());

            if (decrypted != null && (decrypted instanceof String) && decrypted.equals("authorized")) {
                interNodeAuthenticated = true;
            }

        }

        if (interNodeAuthenticated) {
            log.debug("TYPE: inter node cluster request, skip filters");
            chain.proceed(action, request, listener);
            return;
        }

        final Object transportCreds = request.getHeader("searchguard_transport_creds");
        User authenticatedTransportUser = null;
        boolean transportAuthenticated = false;
        if (transportCreds != null && transportCreds instanceof String
                && settings.getAsBoolean(ConfigConstants.SEARCHGUARD_TRANSPORT_AUTH_ENABLED, false)) {

            try {

                final String decodedBasicHeader = new String(DatatypeConverter.parseBase64Binary((String) transportCreds),
                        StandardCharsets.US_ASCII);

                final String username = decodedBasicHeader.split(":")[0];
                final char[] password = decodedBasicHeader.split(":")[1].toCharArray();

                authenticatedTransportUser = backend.authenticate(new AuthCredentials(username, password));
                authorizator.fillRoles(authenticatedTransportUser, new AuthCredentials(authenticatedTransportUser.getName(), null));
                request.putInContext("searchguard_authenticated_user", authenticatedTransportUser);
            } catch (final Exception e) {
                throw new RuntimeException("Transport authentication failed due to " + e, e);
            }

        }

        transportAuthenticated = authenticatedTransportUser != null;

        if (transportAuthenticated) {
            log.debug("TYPE: transport authenticated request, apply filters");
            applySecure(action, request, listener, chain);
            return;
        }

        throw new RuntimeException("Unauthenticated request (SEARCHGUARD_UNAUTH_REQ) for action " + action);
    }

    public abstract void applySecure(final String action, final ActionRequest request, final ActionListener listener,
            final ActionFilterChain chain);

    @Override
    public final void apply(final String action, final ActionResponse response, final ActionListener listener, final ActionFilterChain chain) {
        chain.proceed(action, response, listener);

    }

    protected SearchRequest toSearchRequest(final GetRequest request) {

        final SearchRequest searchRequest = new SearchRequest();
        searchRequest.listenerThreaded(false);
        searchRequest.routing(request.routing());
        searchRequest.copyContextFrom(request);
        searchRequest.preference(request.preference());
        searchRequest.indices(request.indices());
        searchRequest.types(request.type());
        searchRequest.source(SearchSourceBuilder.searchSource().query(new IdsQueryBuilder(request.type()).addIds(request.id())));
        return searchRequest;

    }

    protected MultiSearchRequest toMultiSearchRequest(final MultiGetRequest multiGetRequest) {

        final MultiSearchRequest msearch = new MultiSearchRequest();
        msearch.copyContextFrom(multiGetRequest);
        msearch.listenerThreaded(multiGetRequest.listenerThreaded());

        for (final Iterator<Item> iterator = multiGetRequest.iterator(); iterator.hasNext();) {
            final Item item = iterator.next();

            final SearchRequest st = new SearchRequest();
            st.routing(item.routing());
            st.indices(item.indices());
            st.types(item.type());
            st.listenerThreaded(false);
            st.preference(multiGetRequest.preference());
            st.source(SearchSourceBuilder.searchSource().query(new IdsQueryBuilder(item.type()).addIds(item.id())));
            msearch.add(st);
        }

        return msearch;

    }

    protected void doGet(final GetRequest request, final ActionListener listener, final Client client) {
        client.search(toSearchRequest(request), new DelegatingActionListener<SearchResponse, GetResponse>(listener) {
            @Override
            public GetResponse getDelegatedFromInstigator(final SearchResponse searchResponse) {

                if (searchResponse.getHits().getTotalHits() <= 0) {
                    return new GetResponse(new GetResult(request.index(), request.type(), request.id(), request.version(), false, null,
                            null));
                } else if (searchResponse.getHits().getTotalHits() > 1) {
                    throw new RuntimeException("cannot happen");
                } else {
                    final SearchHit sh = searchResponse.getHits().getHits()[0];
                    return new GetResponse(new GetResult(sh.index(), sh.type(), sh.id(), sh.version(), true, sh.getSourceRef(), null));
                }

            }
        });
    }

    protected void doGet(final MultiGetRequest request, final ActionListener listener, final Client client) {
        client.multiSearch(toMultiSearchRequest(request), new DelegatingActionListener<MultiSearchResponse, GetResponse>(listener) {
            @Override
            public GetResponse getDelegatedFromInstigator(final MultiSearchResponse searchResponse) {

                if (searchResponse.getResponses() == null || searchResponse.getResponses().length <= 0) {
                    final Item item = request.getItems().get(0);
                    return new GetResponse(new GetResult(item.index(), item.type(), item.id(), item.version(), false, null, null));
                } else if (searchResponse.getResponses().length > 1) {
                    throw new RuntimeException("cannot happen");
                } else {
                    final org.elasticsearch.action.search.MultiSearchResponse.Item item = searchResponse.getResponses()[0];
                    final SearchHit sh = item.getResponse().getHits().getHits()[0];
                    return new GetResponse(new GetResult(sh.index(), sh.type(), sh.id(), sh.version(), true, sh.getSourceRef(), null));
                }

            }
        });
    }

}
