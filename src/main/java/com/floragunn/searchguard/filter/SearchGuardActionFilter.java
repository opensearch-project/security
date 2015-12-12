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

import java.io.Serializable;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.audit.AuditListener;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.authorization.ForbiddenException;
import com.floragunn.searchguard.service.SearchGuardConfigService;
import com.floragunn.searchguard.service.SearchGuardService;
import com.floragunn.searchguard.tokeneval.TokenEvaluator;
import com.floragunn.searchguard.tokeneval.TokenEvaluator.Evaluator;
import com.floragunn.searchguard.tokeneval.TokenEvaluator.FilterAction;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class SearchGuardActionFilter implements ActionFilter {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final AuditListener auditListener;
    protected final Authorizator authorizator = null;
    protected final AuthenticationBackend authenticationBackend = null;
    protected final Settings settings;
    protected final ClusterService clusterService;
    protected final Client client;
    protected final SearchGuardConfigService searchGuardConfigService;

    @Inject
    public SearchGuardActionFilter(final Settings settings, final AuditListener auditListener, final ClusterService clusterService,
            final Client client, final SearchGuardConfigService searchGuardConfigService) {
        this.auditListener = auditListener;
        this.settings = settings;
        this.clusterService = clusterService;
        this.client = client;
        this.searchGuardConfigService = searchGuardConfigService;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 1;
    }

    @Override
    public void apply(final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        try {
            apply0(action, request, listener, chain);
        } catch (final ForbiddenException e){
        	log.error("Forbidden while apply() due to {} for action {}", e, e.toString(), action);
        	throw e;
        } catch (final Exception e) {
            log.error("Error while apply() due to {} for action {}", e, e.toString(), action);
            throw new RuntimeException(e);
        }
    }

    private void copyContextToHeader(final ActionRequest request) {
        if (SearchGuardPlugin.DLS_SUPPORTED) {

            final ImmutableOpenMap<Object, Object> map = request.getContext();

            final Iterator it = map.keysIt();

            while (it.hasNext()) {
                final Object key = it.next();

                if (key instanceof String && key.toString().startsWith("searchguard")) {

                    if (request.hasHeader(key.toString())) {
                        continue;
                    }

                    request.putHeader(key.toString(),
                            SecurityUtil.encryptAndSerializeObject((Serializable) map.get(key), SearchGuardService.getSecretKey()));
                    log.trace("Copy from context to header {}", key);

                }

            }

        }
    }

    private void apply0(final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain)
            throws Exception {

        if (action.startsWith("cluster:monitor/")) {
            chain.proceed(action, request, listener);
            return;
        }

        copyContextToHeader(request);

        log.trace("action {} ({}) from {}", action, request.getClass(), request.remoteAddress() == null ? "INTRANODE" : request
                .remoteAddress().toString());

        final User user = request.getFromContext("searchguard_authenticated_user", null);
        final Object authHeader = request.getHeader("searchguard_authenticated_transport_request");

        if (request.remoteAddress() == null && user == null) {
            log.trace("INTRANODE request");
            chain.proceed(action, request, listener);
            return;
        }

        if (user == null) {

            if (authHeader == null || !(authHeader instanceof String)) {
                log.error("not authenticated");
                listener.onFailure(new AuthException("not authenticated"));
            }

            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, SearchGuardService.getSecretKey());

            if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                log.error("bad authenticated");
                listener.onFailure(new AuthException("bad authenticated"));
            }

            log.trace("Authenticated INTERNODE (cluster) message, pass through");
            chain.proceed(action, request, listener);
            return;
        }

        log.trace("user {}", user);

        final boolean allowedForAllIndices = !SecurityUtil.isWildcardMatch(action, "*put*", false)
                && !SecurityUtil.isWildcardMatch(action, "*delete*", false)
                && !SecurityUtil.isWildcardMatch(action, "indices:data*", false)
                && !SecurityUtil.isWildcardMatch(action, "cluster:admin*", false)
                && !SecurityUtil.isWildcardMatch(action, "*close*", false) && !SecurityUtil.isWildcardMatch(action, "*open*", false)
                && !SecurityUtil.isWildcardMatch(action, "*update*", false) && !SecurityUtil.isWildcardMatch(action, "*create*", false);

        final TokenEvaluator evaluator = new TokenEvaluator(searchGuardConfigService.getSecurityConfiguration());
        request.putInContext("_searchguard_token_evaluator", evaluator);

        final List<String> ci = new ArrayList<String>();
        final List<String> aliases = new ArrayList<String>();
        final List<String> types = new ArrayList<String>();

        if (request instanceof IndicesRequest) {
            final IndicesRequest ir = (IndicesRequest) request;
            addType(ir, types, action);
            log.trace("Indices {}", Arrays.toString(ir.indices()));
            log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
            log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());

            ci.addAll(resolveAliases(Arrays.asList(ir.indices())));
            aliases.addAll(getOnlyAliases(Arrays.asList(ir.indices())));

            if (!allowedForAllIndices && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                log.error("Attempt from " + request.remoteAddress() + " to _all indices for " + action + " and " + user);
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);
                //This blocks?
                //listener.onFailure(new AuthException("Attempt from "+request.remoteAddress()+" to _all indices for " + action + "and "+user));
                throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
            }

        }

        if (request instanceof CompositeIndicesRequest) {
            final CompositeIndicesRequest irc = (CompositeIndicesRequest) request;
            final List irs = irc.subRequests();
            for (final Iterator iterator = irs.iterator(); iterator.hasNext();) {
                final IndicesRequest ir = (IndicesRequest) iterator.next();
                addType(ir, types, action);
                log.trace("C Indices {}", Arrays.toString(ir.indices()));
                log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
                log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());

                ci.addAll(resolveAliases(Arrays.asList(ir.indices())));
                aliases.addAll(getOnlyAliases(Arrays.asList(ir.indices())));
                if (!allowedForAllIndices
                        && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                    log.error("Attempt from " + request.remoteAddress() + " to _all indices for " + action + "and " + user);
                    auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);

                    //This blocks?
                    //listener.onFailure(new AuthException("Attempt from "+request.remoteAddress()+" to _all indices for " + action + "and "+user));
                    //break;
                    throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                }

            }
        }

        if (ci.contains(settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX))) {
            auditListener.onMissingPrivileges(user.getName(), request);
            throw new ForbiddenException("Only allowed from localhost (loopback)");

        }

        if (ci.contains("_all")) {
            ci.clear();

            if (!allowedForAllIndices) {
                ci.add("*");
            }

        }

        final InetAddress resolvedAddress = (InetAddress) request.getFromContext("searchguard_resolved_rest_address");

        if (resolvedAddress == null) {
            //not a rest request
            log.debug("Not a rest request, will ignore host rules");

        }

        final Evaluator eval = evaluator.getEvaluator(ci, aliases, types, resolvedAddress, user);

        request.putInContext("searchguard_ac_evaluator", eval);

        copyContextToHeader(request);

        final List<String> filter = request.getFromContext("searchguard_filter", Collections.EMPTY_LIST);

        log.trace("filter {}", filter);

        for (int i = 0; i < filter.size(); i++) {
            final String[] f = filter.get(i).split(":");
            final String ft = f[0];
            final String fn = f[1];

            log.trace("Filter {}. {}/{}", i, ft, fn);

            if (ft.contains("dlsfilter") || ft.contains("flsfilter")) {
                log.trace("    {} skipped here", ft);
                continue;
            }

            final FilterAction faction = eval.evaluateFilter(ft, fn);

            if (faction == FilterAction.BYPASS) {
                log.trace("will bypass");
                continue;
            }

            if ("actionrequestfilter".equals(ft)) {

                final List<String> allowedActions = request.getFromContext("searchguard." + ft + "." + fn + ".allowed_actions",
                        Collections.EMPTY_LIST);
                final List<String> forbiddenActions = request.getFromContext("searchguard." + ft + "." + fn + ".forbidden_actions",
                        Collections.EMPTY_LIST);

                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext();) {
                    final String forbiddenAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, forbiddenAction, false)) {

                        log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, forbiddenAction);
                        auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);
                        //This blocks?
                        //listener.onFailure(new AuthException("Action '" + action + "' is forbidden due to " + forbiddenAction));
                        //break outer;
                        throw new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction);
                    }
                }

                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext();) {
                    final String allowedAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, allowedAction, false)) {
                        log.trace("Action '{}' is allowed due to {}", action, allowedAction);
                        chain.proceed(action, request, listener);
                        return;
                    }
                }

                log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, "DEFAULT");
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);

                //This blocks?
                //listener.onFailure(new AuthException("Action '" + action + "' is forbidden due to DEFAULT"));
                //break outer;
                throw new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action);

            }

            if ("restactionfilter".equals(ft)) {
                final String simpleClassName = request.getFromContext("searchguard." + ft + "." + fn + ".class_name", null);

                final List<String> allowedActions = request.getFromContext("searchguard." + ft + "." + fn + ".allowed_actions",
                        Collections.EMPTY_LIST);
                final List<String> forbiddenActions = request.getFromContext("searchguard." + ft + "." + fn + ".forbidden_actions",
                        Collections.EMPTY_LIST);

                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext();) {
                    final String forbiddenAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(simpleClassName, forbiddenAction, false)) {
                    	throw new ForbiddenException("[{}.{}] Forbidden action {} . Allowed actions: {}", simpleClassName, allowedActions);
                    }
                }

                boolean passall = false;

                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext();) {
                    final String allowedAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(simpleClassName, allowedAction, false)) {
                        passall = true;
                        break;
                    }
                }

                if (!passall) {
                    throw new RuntimeException("[" + ft + "." + fn + "] Unallowed action " + simpleClassName + " . Allowed actions: "
                            + allowedActions);
                }

            }

            //DLS/FLS stuff is not done here, its done on SearchCallback

        }

        chain.proceed(action, request, listener);

    }

    @Override
    public void apply(final String action, final ActionResponse response, final ActionListener listener, final ActionFilterChain chain) {
        chain.proceed(action, response, listener);
    }

    //works also with alias of an alias!
    private List<String> resolveAliases(final List<String> indices) {

        final List<String> result = new ArrayList<String>();

        final ImmutableOpenMap<String, ImmutableOpenMap<String, AliasMetaData>> aliases = clusterService.state().metaData().aliases();

        for (int i = 0; i < indices.size(); i++) {
            final String index = indices.get(i);

            final ImmutableOpenMap<String, AliasMetaData> indexAliases = aliases.get(index);

            if (indexAliases == null || indexAliases.size() == 0) {
                result.add(index);
                log.trace("{} is an concrete index", index);
                continue;
            }

            log.trace("{} is an alias and points to -> {}", index, indexAliases.keys());

            for (final Iterator<org.elasticsearch.common.hppc.cursors.ObjectObjectCursor<String, AliasMetaData>> iterator = indexAliases
                    .iterator(); iterator.hasNext();) {
                final org.elasticsearch.common.hppc.cursors.ObjectObjectCursor<String, AliasMetaData> entry = iterator.next();
                result.add(entry.key);
            }

        }

        return result;

    }

    private List<String> getOnlyAliases(final List<String> indices) {

        final List<String> result = new ArrayList<String>();

        final ImmutableOpenMap<String, ImmutableOpenMap<String, AliasMetaData>> aliases = clusterService.state().metaData().aliases();

        for (int i = 0; i < indices.size(); i++) {
            final String index = indices.get(i);

            final ImmutableOpenMap<String, AliasMetaData> indexAliases = aliases.get(index);

            if (indexAliases == null || indexAliases.size() == 0) {
                continue;
            } else {
                result.add(index);
            }

        }

        return result;

    }

    private void addType(final IndicesRequest request, final List<String> typesl, final String action) {

        try {
            final Method method = request.getClass().getDeclaredMethod("type");
            method.setAccessible(true);
            final String type = (String) method.invoke(request);
            typesl.add(type);
        } catch (final Exception e) {

            try {
                final Method method = request.getClass().getDeclaredMethod("types");
                method.setAccessible(true);
                final String[] types = (String[]) method.invoke(request);
                typesl.addAll(Arrays.asList(types));
            } catch (final Exception e1) {
                log.warn("Cannot determine types for {} ({}) due to type[s]() method not found", action, request.getClass());
            }

        }

    }

}
