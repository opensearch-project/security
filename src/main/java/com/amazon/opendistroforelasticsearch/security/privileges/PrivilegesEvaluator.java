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

package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesAction;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.get.MultiGetAction;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.search.MultiSearchAction;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.search.SearchScrollAction;
import org.elasticsearch.action.termvectors.MultiTermVectorsAction;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.reindex.ReindexAction;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.ActionGroupHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationChangeListener;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.User;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.MultimapBuilder.SetMultimapBuilder;
import com.google.common.collect.SetMultimap;

public class PrivilegesEvaluator implements ConfigurationChangeListener {


    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("opendistro_security_action_trace");
    private final ClusterService clusterService;

    private final IndexNameExpressionResolver resolver;

    private final AuditLog auditLog;
    private ThreadContext threadContext;
    //private final static IndicesOptions DEFAULT_INDICES_OPTIONS = IndicesOptions.lenientExpandOpen();
    private final ConfigurationRepository configurationRepository;

    private PrivilegesInterceptor privilegesInterceptor;

    private final boolean checkSnapshotRestoreWritePrivileges;

    private ConfigConstants.RolesMappingResolution rolesMappingResolution;

    private final ClusterInfoHolder clusterInfoHolder;
    //private final boolean typeSecurityDisabled = false;
    private final ConfigModel configModel;
    private final IndexResolverReplacer irr;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final OpenDistroSecurityIndexAccessEvaluator securityIndexAccessEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;

    private final DlsFlsEvaluator dlsFlsEvaluator;

    private RoleMappingHolder roleMappingHolder = null;
    private TenantHolder tenantHolder = null;
    private final boolean advancedModulesEnabled;

    public PrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool,
                               final ConfigurationRepository configurationRepository, final ActionGroupHolder ah, final IndexNameExpressionResolver resolver,
                               AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor, final ClusterInfoHolder clusterInfoHolder,
                               final IndexResolverReplacer irr, boolean advancedModulesEnabled) {

        super();
        this.configurationRepository = configurationRepository;
        this.clusterService = clusterService;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.privilegesInterceptor = privilegesInterceptor;

        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(settings.get(ConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString()).toUpperCase());
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution",e);
            rolesMappingResolution =  ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }

        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);

        this.clusterInfoHolder = clusterInfoHolder;
        //this.typeSecurityDisabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_DISABLE_TYPE_SECURITY, false);
        configModel = new ConfigModel(ah);
        configurationRepository.subscribeOnChange("roles", configModel);
        configurationRepository.subscribeOnChange("rolesmapping", this);
        this.irr = irr;
        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, auditLog);
        securityIndexAccessEvaluator = new OpenDistroSecurityIndexAccessEvaluator(settings, auditLog);
        dlsFlsEvaluator = new DlsFlsEvaluator(settings, threadPool);
        termsAggregationEvaluator = new TermsAggregationEvaluator();
        tenantHolder = new TenantHolder();
        configurationRepository.subscribeOnChange("roles", tenantHolder);
        this.advancedModulesEnabled = advancedModulesEnabled;
    }

    private class TenantHolder implements ConfigurationChangeListener {

        private SetMultimap<String, Tuple<String, Boolean>> tenantsMM = null;

        public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {

            if (user == null || tenantsMM == null) {
                return Collections.emptyMap();
            }

            final Map<String, Boolean> result = new HashMap<>(roles.size());
            result.put(user.getName(), true);

            tenantsMM.entries().stream().filter(e -> roles.contains(e.getKey())).filter(e -> !user.getName().equals(e.getValue().v1())).forEach(e -> {
                final String tenant = e.getValue().v1();
                final boolean rw = e.getValue().v2();

                if (rw || !result.containsKey(tenant)) { //RW outperforms RO
                    result.put(tenant, rw);
                }
            });
            return Collections.unmodifiableMap(result);
        }

        @Override
        public void onChange(Settings roles) {

            final Set<Future<Tuple<String, Set<Tuple<String, Boolean>>>>> futures = new HashSet<>(roles.size());

            final ExecutorService execs = Executors.newFixedThreadPool(10);

            for (String role : roles.names()) {

                Future<Tuple<String, Set<Tuple<String, Boolean>>>> future = execs.submit(new Callable<Tuple<String, Set<Tuple<String, Boolean>>>>() {
                    @Override
                    public Tuple<String, Set<Tuple<String, Boolean>>> call() throws Exception {
                        final Set<Tuple<String, Boolean>> tuples = new HashSet<>();
                        final Settings tenants = getRolesSettings().getByPrefix(role + ".tenants.");

                        if (tenants != null) {
                            for (String tenant : tenants.names()) {

                                if ("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                                    //RW
                                    tuples.add(new Tuple<String, Boolean>(tenant, true));
                                } else {
                                    //RO
                                    //if(!tenantsMM.containsValue(value)) { //RW outperforms RO
                                    tuples.add(new Tuple<String, Boolean>(tenant, false));
                                    //}
                                }
                            }
                        }

                        return new Tuple<String, Set<Tuple<String, Boolean>>>(role, tuples);
                    }
                });

                futures.add(future);

            }

            execs.shutdown();
            try {
                execs.awaitTermination(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (1) while loading roles");
                return;
            }

            try {
                final SetMultimap<String, Tuple<String, Boolean>> tenantsMM_ = SetMultimapBuilder.hashKeys(futures.size()).hashSetValues(16).build();

                for (Future<Tuple<String, Set<Tuple<String, Boolean>>>> future : futures) {
                    Tuple<String, Set<Tuple<String, Boolean>>> result = future.get();
                    tenantsMM_.putAll(result.v1(), result.v2());
                }

                tenantsMM = tenantsMM_;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (2) while loading roles");
                return;
            } catch (ExecutionException e) {
                log.error("Error while updating roles: {}", e.getCause(), e.getCause());
                throw ExceptionsHelper.convertToElastic(e);
            }

        }
    }

    private class RoleMappingHolder {

        private ListMultimap<String, String> users;
        private ListMultimap<Set<String>, String> abars;
        private ListMultimap<String, String> bars;
        private ListMultimap<String, String> hosts;

        private RoleMappingHolder(Settings rolesMapping) {

            if (rolesMapping != null) {

                final ListMultimap<String, String> users_ = ArrayListMultimap.create();
                final ListMultimap<Set<String>, String> abars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> bars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> hosts_ = ArrayListMultimap.create();

                for (final String roleMap : rolesMapping.names()) {

                    final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);

                    for (String u : roleMapSettings.getAsList(".users")) {
                        users_.put(u, roleMap);
                    }

                    final Set<String> abar = new HashSet<String>(roleMapSettings.getAsList(".and_backendroles"));

                    if (!abar.isEmpty()) {
                        abars_.put(abar, roleMap);
                    }

                    for (String bar : roleMapSettings.getAsList(".backendroles")) {
                        bars_.put(bar, roleMap);
                    }

                    for (String host : roleMapSettings.getAsList(".hosts")) {
                        hosts_.put(host, roleMap);
                    }
                }

                users = users_;
                abars = abars_;
                bars = bars_;
                hosts = hosts_;
            }
        }

        private Set<String> map(final User user, final TransportAddress caller) {

            if (user == null || users == null || abars == null || bars == null || hosts == null) {
                return Collections.emptySet();
            }

            final Set<String> securityRoles = new TreeSet<String>();

            if (rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
                if (log.isDebugEnabled()) {
                    log.debug("Pass backendroles from {}", user);
                }
                securityRoles.addAll(user.getRoles());
            }

            if (((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {

                for (String p : WildcardMatcher.getAllMatchingPatterns(users.keySet(), user.getName())) {
                    securityRoles.addAll(users.get(p));
                }

                for (String p : WildcardMatcher.getAllMatchingPatterns(bars.keySet(), user.getRoles())) {
                    securityRoles.addAll(bars.get(p));
                }

                for (Set<String> p : abars.keySet()) {
                    if (WildcardMatcher.allPatternsMatched(p, user.getRoles())) {
                        securityRoles.addAll(abars.get(p));
                    }
                }

                if (caller != null) {
                    //IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();

                    for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), ipAddress)) {
                        securityRoles.addAll(hosts.get(p));
                    }

                    final String hostResolverMode = getConfigSettings().get("opendistro_security.dynamic.hosts_resolver_mode", "ip-only");

                    if (caller.address() != null
                            && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))) {
                        final String hostName = caller.address().getHostString();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), hostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }

                    if (caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")) {

                        final String resolvedHostName = caller.address().getHostName();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), resolvedHostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }
                }
            }

            return Collections.unmodifiableSet(securityRoles);

        }
    }

    @Override
    public void onChange(Settings rolesMapping) {
        final RoleMappingHolder tmp = new RoleMappingHolder(rolesMapping);
        this.roleMappingHolder = tmp;
    }

    private Settings getRolesSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES);
    }

    private Settings getConfigSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_CONFIG);
    }

    private SecurityRoles getSecurityRoles(Set<String> roles) {
        return configModel.getSecurityRoles().filter(roles);
    }

    public boolean isInitialized() {
        return roleMappingHolder != null && configModel.getSecurityRoles() != null && getRolesSettings() != null && getConfigSettings() != null;
    }

    public PrivilegesEvaluatorResponse evaluate(final User user, String action0, final ActionRequest request, Task task) {

        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Open Distro Security is not initialized.");
        }

        if(action0.startsWith("internal:indices/admin/upgrade")) {
            action0 = "indices:admin/upgrade";
        }

        final TransportAddress caller = Objects.requireNonNull((TransportAddress) this.threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS));
        final Set<String> mappedRoles = mapRoles(user, caller);
        final SecurityRoles securityRoles = getSecurityRoles(mappedRoles);


        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();


        if (log.isDebugEnabled()) {
            log.debug("### evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("action: "+action0+" ("+request.getClass().getSimpleName()+")");
        }

        final Resolved requestedResolved = irr.resolveRequest(request);

        if (log.isDebugEnabled()) {
            log.debug("requestedResolved : {}", requestedResolved );
        }

        // check dlsfls
        if (advancedModulesEnabled
                //&& (action0.startsWith("indices:data/read") || action0.equals(ClusterSearchShardsAction.NAME))
                && dlsFlsEvaluator.evaluate(request, clusterService, resolver, requestedResolved, user, securityRoles, presponse).isComplete()) {
            return presponse;
        }

        // check snapshot/restore requests
        if (snapshotRestoreEvaluator.evaluate(request, task, action0, clusterInfoHolder, presponse).isComplete()) {
            return presponse;
        }

        // Security index access
        if (securityIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, presponse).isComplete()) {
            return presponse;
        }

        final boolean dnfofEnabled =
                getConfigSettings().getAsBoolean("opendistro_security.dynamic.kibana.do_not_fail_on_forbidden", false)
                || getConfigSettings().getAsBoolean("opendistro_security.dynamic.do_not_fail_on_forbidden", false);

        if(log.isTraceEnabled()) {
            log.trace("dnfof enabled? {}", dnfofEnabled);
        }

        final Settings config = getConfigSettings();

        if (isClusterPerm(action0)) {
            if(!securityRoles.impliesClusterPermissionPermission(action0)) {
                presponse.missingPrivileges.add(action0);
                presponse.allowed = false;
                log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", "cluster" , user, requestedResolved, action0, securityRoles.getRoles().stream().map(r->r.getName()).toArray());
                log.info("No permissions for {}", presponse.missingPrivileges);
                return presponse;
            } else {

                if(request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
                    if(log.isDebugEnabled()) {
                        log.debug("Normally allowed but we need to apply some extra checks for a restore request.");
                    }
                } else {


                    if(privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

                        final Boolean replaceResult = privilegesInterceptor.replaceKibanaIndex(request, action0, user, config, requestedResolved, mapTenants(user, mappedRoles));

                        if(log.isDebugEnabled()) {
                            log.debug("Result from privileges interceptor for cluster perm: {}", replaceResult);
                        }

                        if (replaceResult == Boolean.TRUE) {
                            auditLog.logMissingPrivileges(action0, request, task);
                            return presponse;
                        }

                        if (replaceResult == Boolean.FALSE) {
                            presponse.allowed = true;
                            return presponse;
                        }
                    }

                    if (dnfofEnabled
                            && (action0.startsWith("indices:data/read/"))
                            && !requestedResolved.getAllIndices().isEmpty()
                            ) {

                        if(requestedResolved.getAllIndices().isEmpty()) {
                            presponse.missingPrivileges.clear();
                            presponse.allowed = true;
                            return presponse;
                        }


                        Set<String> reduced = securityRoles.reduce(requestedResolved, user, new String[]{action0}, resolver, clusterService);

                        if(reduced.isEmpty()) {
                            presponse.allowed = false;
                            return presponse;
                        }

                        if(irr.replace(request, true, reduced.toArray(new String[0]))) {
                            presponse.missingPrivileges.clear();
                            presponse.allowed = true;
                            return presponse;
                        }
                    }

                    if(log.isDebugEnabled()) {
                        log.debug("Allowed because we have cluster permissions for "+action0);
                    }
                    presponse.allowed = true;
                    return presponse;
                }


            }
        }

        // term aggregations
        if (termsAggregationEvaluator.evaluate(request, clusterService, user, securityRoles, resolver, presponse) .isComplete()) {
            return presponse;
        }

        final Set<String> allIndexPermsRequired = evaluateAdditionalIndexPermissions(request, action0);
        final String[] allIndexPermsRequiredA = allIndexPermsRequired.toArray(new String[0]);

        if(log.isDebugEnabled()) {
            log.debug("requested {} from {}", allIndexPermsRequired, caller);
        }

        presponse.missingPrivileges.clear();
        presponse.missingPrivileges.addAll(allIndexPermsRequired);

        if (log.isDebugEnabled()) {
            log.debug("requested resolved indextypes: {}", requestedResolved);
        }

        if (log.isDebugEnabled()) {
            log.debug("sgr: {}", securityRoles.getRoles().stream().map(d->d.getName()).toArray());
        }


        //TODO exclude Security index

        if(privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

            final Boolean replaceResult = privilegesInterceptor.replaceKibanaIndex(request, action0, user, config, requestedResolved, mapTenants(user, mappedRoles));

            if(log.isDebugEnabled()) {
                log.debug("Result from privileges interceptor: {}", replaceResult);
            }

            if (replaceResult == Boolean.TRUE) {
                auditLog.logMissingPrivileges(action0, request, task);
                return presponse;
            }

            if (replaceResult == Boolean.FALSE) {
                presponse.allowed = true;
                return presponse;
            }
        }

        if (dnfofEnabled
                && (action0.startsWith("indices:data/read/")
                || action0.startsWith("indices:admin/mappings/fields/get")
                || action0.equals("indices:admin/shards/search_shards"))) {

            if(requestedResolved.getAllIndices().isEmpty()) {
                presponse.missingPrivileges.clear();
                presponse.allowed = true;
                return presponse;
            }


            Set<String> reduced = securityRoles.reduce(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

            if(reduced.isEmpty()) {
                presponse.allowed = false;
                return presponse;
            }


            if(irr.replace(request, true, reduced.toArray(new String[0]))) {
                presponse.missingPrivileges.clear();
                presponse.allowed = true;
                return presponse;
            }
        }


        //not bulk, mget, etc request here
        boolean permGiven = false;

        if (config.getAsBoolean("opendistro_security.dynamic.multi_rolespan_enabled", false)) {
            permGiven = securityRoles.impliesTypePermGlobal(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);
        }  else {
            permGiven = securityRoles.get(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

        }

         if (!permGiven) {
            log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", "index" , user, requestedResolved, action0, securityRoles.getRoles().stream().map(r->r.getName()).toArray());
            log.info("No permissions for {}", presponse.missingPrivileges);
        } else {

            if(checkFilteredAliases(requestedResolved.getAllIndices(), action0)) {
                presponse.allowed=false;
                return presponse;
            }

            if(log.isDebugEnabled()) {
                log.debug("Allowed because we have all indices permissions for "+action0);
            }
        }

        presponse.allowed=permGiven;
        return presponse;

    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.roleMappingHolder.map(user, caller);
    }

    /*public Set<String> mapSecurityRoles(final User user, final TransportAddress caller) {

        final Settings rolesMapping = getRolesMappingSettings();
        final Set<String> securityRoles = new TreeSet<String>();

        if(user == null) {
            return Collections.emptySet();
        }

        if(rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
            if(log.isDebugEnabled()) {
                log.debug("Pass backendroles from {}", user);
            }
            securityRoles.addAll(user.getRoles());
        }

        if(rolesMapping != null && ((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {
            for (final String roleMap : rolesMapping.names()) {
                final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);

                if (WildcardMatcher.allPatternsMatched(roleMapSettings.getAsList(".and_backendroles", Collections.emptyList()).toArray(new String[0]), userRoles))) {
                    securityRoles.add(roleMap);
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".backendroles", Collections.emptyList()).toArray(new String[0]), userRoles)) {
                    securityRoles.add(roleMap);
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".users"), user.getName())) {
                    securityRoles.add(roleMap);
                    continue;
                }

                if(caller != null && log.isTraceEnabled()) {
                    log.trace("caller (getAddress()) is {}", caller.getAddress());
                    log.trace("caller unresolved? {}", caller.address().isUnresolved());
                    log.trace("caller inner? {}", caller.address().getAddress()==null?"<unresolved>":caller.address().getAddress().toString());
                    log.trace("caller (getHostString()) is {}", caller.address().getHostString());
                    log.trace("caller (getHostName(), dns) is {}", caller.address().getHostName()); //reverse lookup
                }

                if(caller != null) {
                    //IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();
                    if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), ipAddress)) {
                        securityRoles.add(roleMap);
                        continue;
                    }

                    final String hostResolverMode = getConfigSettings().get("opendistro_security.dynamic.hosts_resolver_mode","ip-only");

                    if(caller.address() != null && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))){
                        final String hostName = caller.address().getHostString();

                        if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), hostName)) {
                            securityRoles.add(roleMap);
                            continue;
                        }
                    }

                    if(caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")){

                        final String resolvedHostName = caller.address().getHostName();

                        if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), resolvedHostName)) {
                            securityRoles.add(roleMap);
                            continue;
                        }
                    }
                }
            }
        }

        return Collections.unmodifiableSet(securityRoles);

    }*/

    public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {
        return this.tenantHolder.mapTenants(user, roles);
    }


    /*public Map<String, Boolean> mapTenants(final User user, final TransportAddress caller) {

        if(user == null) {
            return Collections.emptyMap();
        }

        final Map<String, Boolean> result = new HashMap<>();
        result.put(user.getName(), true);

        for(String securityRole: mapSecurityRoles(user, caller)) {
            Settings tenants = getRolesSettings().getByPrefix(securityRole+".tenants.");

            if(tenants != null) {
                for(String tenant: tenants.names()) {

                    if(tenant.equals(user.getName())) {
                        continue;
                    }

                    if("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                        result.put(tenant, true);
                    } else {
                        if(!result.containsKey(tenant)) { //RW outperforms RO
                            result.put(tenant, false);
                        }
                    }
                }
            }

        }

        return Collections.unmodifiableMap(result);
    }*/

    public Set<String> getAllConfiguredTenantNames() {

        final Settings roles = getRolesSettings();

    	if(roles == null || roles.isEmpty()) {
    		return Collections.emptySet();
    	}

    	final Set<String> configuredTenants = new HashSet<>();
    	for(String securityRole: roles.names()) {
            Settings tenants = roles.getByPrefix(securityRole+".tenants.");

            if(tenants != null) {
                configuredTenants.addAll(tenants.names());
            }

        }

    	return Collections.unmodifiableSet(configuredTenants);
    }

    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("opendistro_security.dynamic.kibana.multitenancy_enabled", true);
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("opendistro_security.dynamic.kibana.do_not_fail_on_forbidden", false);
    }

    public String kibanaIndex() {
        return getConfigSettings().get("opendistro_security.dynamic.kibana.index",".kibana");
    }

    public String kibanaServerUsername() {
        return getConfigSettings().get("opendistro_security.dynamic.kibana.server_username","kibanaserver");
    }

    private Set<String> evaluateAdditionalIndexPermissions(final ActionRequest request, final String originalAction) {
      //--- check inner bulk requests
        final Set<String> additionalPermissionsRequired = new HashSet<>();

        if(!isClusterPerm(originalAction)) {
            additionalPermissionsRequired.add(originalAction);
        }

        if (request instanceof ClusterSearchShardsRequest) {
            additionalPermissionsRequired.add(SearchAction.NAME);
        }

        if (request instanceof BulkShardRequest) {
            BulkShardRequest bsr = (BulkShardRequest) request;
            for (BulkItemRequest bir : bsr.items()) {
                switch (bir.request().opType()) {
                case CREATE:
                    additionalPermissionsRequired.add(IndexAction.NAME);
                    break;
                case INDEX:
                    additionalPermissionsRequired.add(IndexAction.NAME);
                    break;
                case DELETE:
                    additionalPermissionsRequired.add(DeleteAction.NAME);
                    break;
                case UPDATE:
                    additionalPermissionsRequired.add(UpdateAction.NAME);
                    break;
                }
            }
        }

        if (request instanceof IndicesAliasesRequest) {
            IndicesAliasesRequest bsr = (IndicesAliasesRequest) request;
            for (AliasActions bir : bsr.getAliasActions()) {
                switch (bir.actionType()) {
                case REMOVE_INDEX:
                    additionalPermissionsRequired.add(DeleteIndexAction.NAME);
                    break;
                default:
                    break;
                }
            }
        }

        if (request instanceof CreateIndexRequest) {
            CreateIndexRequest cir = (CreateIndexRequest) request;
            if(cir.aliases() != null && !cir.aliases().isEmpty()) {
                additionalPermissionsRequired.add(IndicesAliasesAction.NAME);
            }
        }

        if(request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
            additionalPermissionsRequired.addAll(ConfigConstants.OPENDISTRO_SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES);
        }

        if(actionTrace.isTraceEnabled() && additionalPermissionsRequired.size() > 1) {
            actionTrace.trace(("Additional permissions required: "+additionalPermissionsRequired));
        }

        if(log.isDebugEnabled() && additionalPermissionsRequired.size() > 1) {
            log.debug("Additional permissions required: "+additionalPermissionsRequired);
        }

        return Collections.unmodifiableSet(additionalPermissionsRequired);
    }

    private static boolean isClusterPerm(String action0) {
        return  (    action0.startsWith("cluster:")
                || action0.startsWith("indices:admin/template/")

            || action0.startsWith(SearchScrollAction.NAME)
            || (action0.equals(BulkAction.NAME))
            || (action0.equals(MultiGetAction.NAME))
            || (action0.equals(MultiSearchAction.NAME))
            || (action0.equals(MultiTermVectorsAction.NAME))
            || (action0.equals(ReindexAction.NAME))

            ) ;
    }

    private boolean checkFilteredAliases(Set<String> requestedResolvedIndices, String action) {
        //check filtered aliases
        for(String requestAliasOrIndex: requestedResolvedIndices) {

            final List<AliasMetaData> filteredAliases = new ArrayList<AliasMetaData>();

            final IndexMetaData indexMetaData = clusterService.state().metaData().getIndices().get(requestAliasOrIndex);

            if(indexMetaData == null) {
                log.debug("{} does not exist in cluster metadata", requestAliasOrIndex);
                continue;
            }

            final ImmutableOpenMap<String, AliasMetaData> aliases = indexMetaData.getAliases();

            if(aliases != null && aliases.size() > 0) {

                if(log.isDebugEnabled()) {
                    log.debug("Aliases for {}: {}", requestAliasOrIndex, aliases);
                }

                final Iterator<String> it = aliases.keysIt();
                while(it.hasNext()) {
                    final String alias = it.next();
                    final AliasMetaData aliasMetaData = aliases.get(alias);

                    if(aliasMetaData != null && aliasMetaData.filteringRequired()) {
                        filteredAliases.add(aliasMetaData);
                        if(log.isDebugEnabled()) {
                            log.debug(alias+" is a filtered alias "+aliasMetaData.getFilter());
                        }
                    } else {
                        if(log.isDebugEnabled()) {
                            log.debug(alias+" is not an alias or does not have a filter");
                        }
                    }
                }
            }

            if(filteredAliases.size() > 1 && WildcardMatcher.match("indices:data/read/*search*", action)) {
                //TODO add queries as dls queries (works only if dls module is installed)
                final String faMode = getConfigSettings().get("opendistro_security.dynamic.filtered_alias_mode","warn");

                if(faMode.equals("warn")) {
                    log.warn("More than one ({}) filtered alias found for same index ({}). This is currently not recommended. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                } else if (faMode.equals("disallow")) {
                    log.error("More than one ({}) filtered alias found for same index ({}). This is currently not supported. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("More than one ({}) filtered alias found for same index ({}). Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                    }
                }
            }
        } //end-for

        return false;
    }

    private List<String> toString(List<AliasMetaData> aliases) {
        if(aliases == null || aliases.size() == 0) {
            return Collections.emptyList();
        }

        final List<String> ret = new ArrayList<>(aliases.size());

        for(final AliasMetaData amd: aliases) {
            if(amd != null) {
                ret.add(amd.alias());
            }
        }

        return Collections.unmodifiableList(ret);
    }
}
