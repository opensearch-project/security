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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.opensearch.security.auditlog.NullAuditLog;
import org.opensearch.security.auditlog.impl.AuditLogImpl;
import org.opensearch.security.compliance.ComplianceIndexingOperationListenerImpl;
import org.opensearch.security.configuration.DlsFlsValveImpl;
import org.opensearch.security.configuration.SecurityFlsDlsIndexSearcherWrapper;
import org.opensearch.security.configuration.PrivilegesInterceptorImpl;
import org.opensearch.security.configuration.Salt;
import org.opensearch.security.dlic.rest.api.SecurityRestApiActions;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.http.SecurityHttpServerTransport;
import org.opensearch.security.ssl.OpenSearchSecuritySSLPlugin;
import org.opensearch.security.ssl.rest.SecuritySSLReloadCertsAction;
import org.opensearch.security.ssl.rest.SecuritySSLCertsInfoAction;
import org.opensearch.security.ssl.transport.DefaultPrincipalExtractor;
import org.opensearch.security.transport.SecurityInterceptor;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.setting.TransportPassiveAuthSetting;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.apache.lucene.search.QueryCachingPolicy;
import org.apache.lucene.search.Weight;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.Version;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.component.Lifecycle.State;
import org.opensearch.common.component.LifecycleComponent;
import org.opensearch.common.component.LifecycleListener;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.NamedWriteableRegistry;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.network.NetworkModule;
import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.common.util.BigArrays;
import org.opensearch.common.util.PageCacheRecycler;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.http.HttpServerTransport;
import org.opensearch.http.HttpServerTransport.Dispatcher;
import org.opensearch.index.Index;
import org.opensearch.index.IndexModule;
import org.opensearch.index.cache.query.QueryCache;
import org.opensearch.index.shard.SearchOperationListener;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.indices.breaker.CircuitBreakerService;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.MapperPlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestStatus;
import org.opensearch.script.ScriptService;
import org.opensearch.search.internal.InternalScrollSearchRequest;
import org.opensearch.search.internal.ReaderContext;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.query.QuerySearchResult;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.TransportConfigUpdateAction;
import org.opensearch.security.action.whoami.TransportWhoAmIAction;
import org.opensearch.security.action.whoami.WhoAmIAction;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.AuditLogSslExceptionHandler;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.compliance.ComplianceIndexingOperationListener;
import org.opensearch.security.filter.SecurityFilter;
import org.opensearch.security.http.SecurityNonSslHttpServerTransport;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesInterceptor;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.rest.DashboardsInfoAction;
import org.opensearch.security.rest.SecurityHealthAction;
import org.opensearch.security.rest.SecurityInfoAction;
import org.opensearch.security.rest.TenantInfoAction;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.SecuritySSLNettyTransport;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.transport.DefaultInterClusterRequestEvaluator;
import org.opensearch.security.transport.InterClusterRequestEvaluator;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.RemoteClusterService;
import org.opensearch.transport.Transport;
import org.opensearch.transport.Transport.Connection;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportInterceptor;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;
import org.opensearch.transport.TransportRequestOptions;
import org.opensearch.transport.TransportResponse;
import org.opensearch.transport.TransportResponseHandler;
import org.opensearch.transport.TransportService;
import org.opensearch.watcher.ResourceWatcherService;

import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.DlsFlsRequestValve;
import org.opensearch.security.ssl.http.netty.ValidatingDispatcher;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.ModuleInfo;
import org.opensearch.security.support.ReflectionHelper;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.security.support.SecuritySettings;
import com.google.common.collect.Lists;

public final class OpenSearchSecurityPlugin extends OpenSearchSecuritySSLPlugin implements ClusterPlugin, MapperPlugin {

    private static final String KEYWORD = ".keyword";
    private static final Logger actionTrace = LoggerFactory.getLogger("opendistro_security_action_trace");
    private static final DeprecationLogger deprecationLogger = DeprecationLogger.getLogger(OpenSearchSecurityPlugin.class);

    public static final String LEGACY_OPENDISTRO_PREFIX = "_opendistro/_security";
    public static final String PLUGINS_PREFIX = "_plugins/_security";

    private boolean sslCertReloadEnabled;
    private volatile SecurityRestFilter securityRestHandler;
    private volatile SecurityInterceptor si;
    private volatile PrivilegesEvaluator evaluator;
    private volatile ThreadPool threadPool;
    private volatile ConfigurationRepository cr;
    private volatile AdminDNs adminDns;
    private volatile ClusterService cs;
    private volatile AuditLog auditLog;
    private volatile BackendRegistry backendRegistry;
    private volatile SslExceptionHandler sslExceptionHandler;
    private volatile Client localClient;
    private final boolean disabled;
    private final List<String> demoCertHashes = new ArrayList<String>(3);
    private volatile SecurityFilter sf;
    private volatile IndexResolverReplacer irr;
    private volatile NamedXContentRegistry namedXContentRegistry = null;
    private volatile DlsFlsRequestValve dlsFlsValve = null;
    private volatile Salt salt;
    private volatile OpensearchDynamicSetting<Boolean> transportPassiveAuthSetting;

    public static boolean isActionTraceEnabled() {
        return actionTrace.isTraceEnabled();
    }

    public static void traceAction(String message) {
        actionTrace.trace(message);
    }

    public static void traceAction(String message, Object p0) {
        actionTrace.trace(message, p0);
    }

    @Override
    public void close() throws IOException {
        super.close();
        if (auditLog != null) {
            auditLog.close();
        }
    }

    private final SslExceptionHandler evaluateSslExceptionHandler() {
        if (client || disabled || SSLConfig.isSslOnlyMode()) {
            return new SslExceptionHandler(){};
        }

        return Objects.requireNonNull(sslExceptionHandler);
    }

    private static boolean isDisabled(final Settings settings) {
        return settings.getAsBoolean(ConfigConstants.SECURITY_DISABLED, false);
    }

    /**
     * SSL Cert Reload will be enabled only if security is not disabled and not in we are not using sslOnly mode.
     * @param settings Elastic configuration settings
     * @return true if ssl cert reload is enabled else false
     */
    private static boolean isSslCertReloadEnabled(final Settings settings) {
        return settings.getAsBoolean(ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED, false);
    }

    public OpenSearchSecurityPlugin(final Settings settings, final Path configPath) {
        super(settings, configPath, isDisabled(settings));

        disabled = isDisabled(settings);
        sslCertReloadEnabled = isSslCertReloadEnabled(settings);

        transportPassiveAuthSetting = new TransportPassiveAuthSetting(settings);

        if (disabled) {
            this.sslCertReloadEnabled = false;
            log.warn("OpenSearch Security plugin installed but disabled. This can expose your configuration (including passwords) to the public.");
            return;
        }

        if (SSLConfig.isSslOnlyMode()) {
            this.sslCertReloadEnabled = false;
            log.warn("OpenSearch Security plugin run in ssl only mode. No authentication or authorization is performed");
            return;
        }


        demoCertHashes.add("54a92508de7a39d06242a0ffbf59414d7eb478633c719e6af03938daf6de8a1a");
        demoCertHashes.add("742e4659c79d7cad89ea86aab70aea490f23bbfc7e72abd5f0a5d3fb4c84d212");
        demoCertHashes.add("db1264612891406639ecd25c894f256b7c5a6b7e1d9054cbe37b77acd2ddd913");
        demoCertHashes.add("2a5398e20fcb851ec30aa141f37233ee91a802683415be2945c3c312c65c97cf");
        demoCertHashes.add("33129547ce617f784c04e965104b2c671cce9e794d1c64c7efe58c77026246ae");
        demoCertHashes.add("c4af0297cc75546e1905bdfe3934a950161eee11173d979ce929f086fdf9794d");
        demoCertHashes.add("7a355f42c90e7543a267fbe3976c02f619036f5a34ce712995a22b342d83c3ce");
        demoCertHashes.add("a9b5eca1399ec8518081c0d4a21a34eec4589087ce64c04fb01a488f9ad8edc9");

        //new certs 04/2018
        demoCertHashes.add("d14aefe70a592d7a29e14f3ff89c3d0070c99e87d21776aa07d333ee877e758f");
        demoCertHashes.add("54a70016e0837a2b0c5658d1032d7ca32e432c62c55f01a2bf5adcb69a0a7ba9");
        demoCertHashes.add("bdc141ab2272c779d0f242b79063152c49e1b06a2af05e0fd90d505f2b44d5f5");
        demoCertHashes.add("3e839e2b059036a99ee4f742814995f2fb0ced7e9d68a47851f43a3c630b5324");
        demoCertHashes.add("9b13661c073d864c28ad7b13eda67dcb6cbc2f04d116adc7c817c20b4c7ed361");

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                if(Security.getProvider("BC") == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }
                return null;
            }
        });

        final String advancedModulesEnabledKey = ConfigConstants.SECURITY_ADVANCED_MODULES_ENABLED;
        if (settings.hasValue(advancedModulesEnabledKey)) {
            deprecationLogger.deprecate("Setting {} is ignored.", advancedModulesEnabledKey);
        }

        log.info("Clustername: {}", settings.get("cluster.name","opensearch"));

        if (!transportSSLEnabled && !SSLConfig.isSslOnlyMode()) {
            throw new IllegalStateException(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }

        if(!client) {
            final List<Path> filesWithWrongPermissions = AccessController.doPrivileged(new PrivilegedAction<List<Path>>() {
                @Override
                public List<Path> run() {
                  final Path confPath = new Environment(settings, configPath).configFile().toAbsolutePath();
                    if(Files.isDirectory(confPath, LinkOption.NOFOLLOW_LINKS)) {
                        try (Stream<Path> s = Files.walk(confPath)) {
                            return s.distinct().filter(p -> checkFilePermissions(p)).collect(Collectors.toList());
                        } catch (Exception e) {
                            log.error(e.toString());
                            return null;
                        }
                    }

                    return Collections.emptyList();
                }
            });

            if(filesWithWrongPermissions != null && filesWithWrongPermissions.size() > 0) {
                for(final Path p: filesWithWrongPermissions) {
                    if(Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
                        log.warn("Directory {} has insecure file permissions (should be 0700)", p);
                    } else {
                        log.warn("File {} has insecure file permissions (should be 0600)", p);
                    }
                }
            }
        }

        if(!client && !settings.getAsBoolean(ConfigConstants.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, false)) {
            //check for demo certificates
            final List<String> files = AccessController.doPrivileged(new PrivilegedAction<List<String>>() {
                @Override
                public List<String> run() {
                  final Path confPath = new Environment(settings, configPath).configFile().toAbsolutePath();
                    if(Files.isDirectory(confPath, LinkOption.NOFOLLOW_LINKS)) {
                        try (Stream<Path> s = Files.walk(confPath)) {
                            return s.distinct().map(p -> sha256(p)).collect(Collectors.toList());
                        } catch (Exception e) {
                            log.error(e.toString());
                            return null;
                        }
                    }

                    return Collections.emptyList();
                }
            });

            if(files != null) {
                demoCertHashes.retainAll(files);
                if(!demoCertHashes.isEmpty()) {
                    log.error("Demo certificates found but "+ConfigConstants.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES+" is set to false.");
                    throw new RuntimeException("Demo certificates found "+demoCertHashes);
                }
            } else {
                throw new RuntimeException("Unable to look for demo certificates");
            }

        }
    }

    private String sha256(Path p) {

        if(!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
            return "";
        }

        if(!Files.isReadable(p)) {
            log.debug("Unreadable file "+p+" found");
            return "";
        }

        try {
            MessageDigest digester = MessageDigest.getInstance("SHA256");
            final String hash = org.bouncycastle.util.encoders.Hex.toHexString(digester.digest(Files.readAllBytes(p)));
            log.debug(hash +" :: "+p);
            return hash;
        } catch (Exception e) {
            throw new OpenSearchSecurityException("Unable to digest file "+p, e);
        }
    }

    private boolean checkFilePermissions(final Path p) {

        if (p == null) {
            return false;
        }


        Set<PosixFilePermission> perms;

        try {
            perms = Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS);
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Cannot determine posix file permissions for {} due to {}", p, e);
            }
            //ignore, can happen on windows
            return false;
        }

        if(Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
            if (perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                // no x for others must be set
                return true;
            }
        } else {
            if (perms.contains(PosixFilePermission.OWNER_EXECUTE) || perms.contains(PosixFilePermission.GROUP_EXECUTE)
                    || perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                // no x must be set
                return true;
            }
        }


        if (perms.contains(PosixFilePermission.OTHERS_READ) || perms.contains(PosixFilePermission.OTHERS_WRITE)) {
            // no permissions for "others" allowed
            return true;
        }

        //if (perms.contains(PosixFilePermission.GROUP_READ) || perms.contains(PosixFilePermission.GROUP_WRITE)) {
        //    // no permissions for "group" allowed
        //    return true;
        //}

        return false;
    }


    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {

        final List<RestHandler> handlers = new ArrayList<RestHandler>(1);

        if (!client && !disabled) {

            handlers.addAll(super.getRestHandlers(settings, restController, clusterSettings, indexScopedSettings, settingsFilter, indexNameExpressionResolver, nodesInCluster));

            if(!SSLConfig.isSslOnlyMode()) {
                handlers.add(new SecurityInfoAction(settings, restController, Objects.requireNonNull(evaluator), Objects.requireNonNull(threadPool)));
                handlers.add(new SecurityHealthAction(settings, restController, Objects.requireNonNull(backendRegistry)));
                handlers.add(new SecuritySSLCertsInfoAction(settings, restController, sks, Objects.requireNonNull(threadPool), Objects.requireNonNull(adminDns)));
                handlers.add(new DashboardsInfoAction(settings, restController, Objects.requireNonNull(evaluator), Objects.requireNonNull(threadPool)));
                handlers.add(new TenantInfoAction(settings, restController, Objects.requireNonNull(evaluator), Objects.requireNonNull(threadPool),
				Objects.requireNonNull(cs), Objects.requireNonNull(adminDns), Objects.requireNonNull(cr)));

                if (sslCertReloadEnabled) {
                    handlers.add(new SecuritySSLReloadCertsAction(settings, restController, sks, Objects.requireNonNull(threadPool), Objects.requireNonNull(adminDns)));
                }
                final Collection<RestHandler> apiHandlers = SecurityRestApiActions.getHandler(settings, configPath, restController, localClient, adminDns, cr, cs, principalExtractor, evaluator, threadPool, Objects.requireNonNull(auditLog));
                handlers.addAll(apiHandlers);
                log.debug("Added {} management rest handler(s)", apiHandlers.size());
            }
        }

        return handlers;
    }

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(final ThreadContext threadContext) {

        if(client || disabled || SSLConfig.isSslOnlyMode()) {
            return (rh) -> rh;
        }

        return (rh) -> securityRestHandler.wrap(rh, adminDns);
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> actions = new ArrayList<>(1);
        if(!disabled && !SSLConfig.isSslOnlyMode()) {
            actions.add(new ActionHandler<>(ConfigUpdateAction.INSTANCE, TransportConfigUpdateAction.class));
            actions.add(new ActionHandler<>(WhoAmIAction.INSTANCE, TransportWhoAmIAction.class));
        }
        return actions;
    }

    @Override
    public void onIndexModule(IndexModule indexModule) {
        //called for every index!

        if (!disabled && !client && !SSLConfig.isSslOnlyMode()) {
            log.debug("Handle auditLog {} for onIndexModule() of index {}", auditLog.getClass(), indexModule.getIndex().getName());

            final ComplianceIndexingOperationListener ciol = new ComplianceIndexingOperationListenerImpl(auditLog);
            indexModule.addIndexOperationListener(ciol);

            indexModule.setReaderWrapper(indexService -> new SecurityFlsDlsIndexSearcherWrapper(indexService, settings, adminDns, cs, auditLog, ciol, evaluator, salt));
            indexModule.forceQueryCacheProvider((indexSettings,nodeCache)->new QueryCache() {

                @Override
                public Index index() {
                    return indexSettings.getIndex();
                }

                @Override
                public void close() throws OpenSearchException {
                    clear("close");
                }

                @Override
                public void clear(String reason) {
                    nodeCache.clearIndex(index().getName());
                }

                @Override
                public Weight doCache(Weight weight, QueryCachingPolicy policy) {
                    final Map<String, Set<String>> allowedFlsFields = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadPool.getThreadContext(),
                            ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER);

                    if(SecurityUtils.evalMap(allowedFlsFields, index().getName()) != null) {
                        return weight;
                    } else {

                        final Map<String, Set<String>> maskedFieldsMap = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadPool.getThreadContext(),
                                ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);

                        if(SecurityUtils.evalMap(maskedFieldsMap, index().getName()) != null) {
                            return weight;
                        } else {
                            return nodeCache.doCache(weight, policy);
                        }
                    }

                }
            });

            indexModule.addSearchOperationListener(new SearchOperationListener() {

                @Override
                public void onPreQueryPhase(SearchContext context) {
                    dlsFlsValve.handleSearchContext(context, threadPool, namedXContentRegistry);
                }

                @Override
                public void onNewReaderContext(ReaderContext readerContext) {
                    final boolean interClusterRequest = HeaderHelper.isInterClusterRequest(threadPool.getThreadContext());
                    if (Origin.LOCAL.toString().equals(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN))
                            && (interClusterRequest || HeaderHelper.isDirectRequest(threadPool.getThreadContext()))

                    ) {
                        readerContext.putInContext("_opendistro_security_scroll_auth_local", Boolean.TRUE);
                    } else {
                        readerContext.putInContext("_opendistro_security_scroll_auth", threadPool.getThreadContext()
                                .getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER));
                    }
                }

                @Override
                public void onNewScrollContext(ReaderContext readerContext) {
                    final boolean interClusterRequest = HeaderHelper.isInterClusterRequest(threadPool.getThreadContext());
                    if (Origin.LOCAL.toString().equals(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN))
                            && (interClusterRequest || HeaderHelper.isDirectRequest(threadPool.getThreadContext()))

                    ) {
                        readerContext.putInContext("_opendistro_security_scroll_auth_local", Boolean.TRUE);
                    } else {
                        readerContext.putInContext("_opendistro_security_scroll_auth", threadPool.getThreadContext()
                                .getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER));
                    }
                }

                @Override
                public void validateReaderContext(ReaderContext readerContext, TransportRequest transportRequest) {
                    if (transportRequest instanceof InternalScrollSearchRequest) {
                        final Object _isLocal = readerContext.getFromContext("_opendistro_security_scroll_auth_local");
                        final Object _user = readerContext.getFromContext("_opendistro_security_scroll_auth");
                        if (_user != null && (_user instanceof User)) {
                            final User scrollUser = (User) _user;
                            final User currentUser = threadPool.getThreadContext()
                                    .getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                            if (!scrollUser.equals(currentUser)) {
                                auditLog.logMissingPrivileges(SearchScrollAction.NAME, transportRequest, null);
                                log.error("Wrong user {} in reader context, expected {}", scrollUser, currentUser);
                                throw new OpenSearchSecurityException("Wrong user in reader context", RestStatus.FORBIDDEN);
                            }
                        } else if (_isLocal != Boolean.TRUE) {
                            auditLog.logMissingPrivileges(SearchScrollAction.NAME, transportRequest, null);
                            throw new OpenSearchSecurityException("No user in reader context", RestStatus.FORBIDDEN);
                        }
                    }
                }

                @Override
                public void onQueryPhase(SearchContext searchContext, long tookInNanos) {
                    QuerySearchResult queryResult = searchContext.queryResult();
                    assert queryResult != null;
                    if (!queryResult.hasAggs()) {
                        return;
                    }

                    final Map<String, Set<String>> maskedFieldsMap = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadPool.getThreadContext(),
                            ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);
                    final String maskedEval = SecurityUtils.evalMap(maskedFieldsMap, indexModule.getIndex().getName());
                    if (maskedEval != null) {
                        final Set<String> mf = maskedFieldsMap.get(maskedEval);
                        if (mf != null && !mf.isEmpty()) {
                            dlsFlsValve.onQueryPhase(queryResult);
                        }
                    }
                }
            });
        }
    }

    @Override
    public List<ActionFilter> getActionFilters() {
        List<ActionFilter> filters = new ArrayList<>(1);
        if (!client && !disabled && !SSLConfig.isSslOnlyMode()) {
            filters.add(Objects.requireNonNull(sf));
        }
        return filters;
    }

    @Override
    public List<TransportInterceptor> getTransportInterceptors(NamedWriteableRegistry namedWriteableRegistry, ThreadContext threadContext) {
        List<TransportInterceptor> interceptors = new ArrayList<TransportInterceptor>(1);

        if (!client && !disabled && !SSLConfig.isSslOnlyMode()) {
            interceptors.add(new TransportInterceptor() {

                @Override
                public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(String action, String executor,
                        boolean forceExecution, TransportRequestHandler<T> actualHandler) {

                    return new TransportRequestHandler<T>() {

                        @Override
                        public void messageReceived(T request, TransportChannel channel, Task task) throws Exception {
                            si.getHandler(action, actualHandler).messageReceived(request, channel, task);
                        }
                    };

                }

                @Override
                public AsyncSender interceptSender(AsyncSender sender) {

                    return new AsyncSender() {

                        @Override
                        public <T extends TransportResponse> void sendRequest(Connection connection, String action,
                                TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {
                            si.sendRequestDecorate(sender, connection, action, request, options, handler);
                        }
                    };
                }
            });
        }

        return interceptors;
    }

    @Override
    public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, PageCacheRecycler pageCacheRecycler,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {
        Map<String, Supplier<Transport>> transports = new HashMap<String, Supplier<Transport>>();

        if(SSLConfig.isSslOnlyMode()) {
            return super.getTransports(settings, threadPool, pageCacheRecycler, circuitBreakerService, namedWriteableRegistry, networkService);
        }

        if (transportSSLEnabled) {
            transports.put("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport",
                    () -> new SecuritySSLNettyTransport(settings, Version.CURRENT, threadPool, networkService, pageCacheRecycler,
                            namedWriteableRegistry, circuitBreakerService, sks, evaluateSslExceptionHandler(), sharedGroupFactory, SSLConfig));
        }
        return transports;
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            PageCacheRecycler pageCacheRecycler, CircuitBreakerService circuitBreakerService, NamedXContentRegistry xContentRegistry,
            NetworkService networkService, Dispatcher dispatcher, ClusterSettings clusterSettings) {

        if(SSLConfig.isSslOnlyMode()) {
            return super.getHttpTransports(settings, threadPool, bigArrays, pageCacheRecycler, circuitBreakerService, xContentRegistry,
             networkService, dispatcher, clusterSettings);
        }

        if(!disabled) {
            if (!client && httpSSLEnabled) {

                final ValidatingDispatcher validatingDispatcher = new ValidatingDispatcher(threadPool.getThreadContext(), dispatcher,
                        settings, configPath, evaluateSslExceptionHandler());
                //TODO close odshst
                final SecurityHttpServerTransport odshst = new SecurityHttpServerTransport(settings, networkService, bigArrays,
                        threadPool, sks, evaluateSslExceptionHandler(), xContentRegistry, validatingDispatcher, clusterSettings, sharedGroupFactory);

                return Collections.singletonMap("org.opensearch.security.http.SecurityHttpServerTransport",
                        () -> odshst);
            } else if (!client) {
                return Collections.singletonMap("org.opensearch.security.http.SecurityHttpServerTransport",
                        () -> new SecurityNonSslHttpServerTransport(settings, networkService, bigArrays, threadPool, xContentRegistry, dispatcher, clusterSettings, sharedGroupFactory));
            }
        }
        return Collections.emptyMap();
    }



    @Override
    public Collection<Object> createComponents(Client localClient, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry,
            Environment environment, NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver, Supplier<RepositoriesService> repositoriesServiceSupplier) {

        SSLConfig.registerClusterSettingsChangeListener(clusterService.getClusterSettings());
        if(SSLConfig.isSslOnlyMode()) {
            return super.createComponents(
                    localClient,
                    clusterService,
                    threadPool,
                    resourceWatcherService,
                    scriptService,
                    xContentRegistry,
                    environment,
                    nodeEnvironment,
                    namedWriteableRegistry,
                    indexNameExpressionResolver,
                    repositoriesServiceSupplier
            );
        }

        this.threadPool = threadPool;
        this.cs = clusterService;
        this.localClient = localClient;

        final List<Object> components = new ArrayList<Object>();

        if (client || disabled) {
            return components;
        }

        //Register opensearch dynamic settings
        transportPassiveAuthSetting.registerClusterSettingsChangeListener(clusterService.getClusterSettings());

        final ClusterInfoHolder cih = new ClusterInfoHolder();
        this.cs.addListener(cih);
        this.salt = Salt.from(settings);

        final IndexNameExpressionResolver resolver = new IndexNameExpressionResolver(threadPool.getThreadContext());
        irr = new IndexResolverReplacer(resolver, clusterService, cih);

        final String DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = DefaultInterClusterRequestEvaluator.class.getName();
        InterClusterRequestEvaluator interClusterRequestEvaluator = new DefaultInterClusterRequestEvaluator(settings);

        final String className = settings.get(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS);
        log.debug("Using {} as intercluster request evaluator class", className);
        if (!DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS.equals(className)) {
            interClusterRequestEvaluator = ReflectionHelper.instantiateInterClusterRequestEvaluator(className, settings);
        }

        final PrivilegesInterceptor privilegesInterceptor;

        if (SSLConfig.isSslOnlyMode()) {
            dlsFlsValve = new DlsFlsRequestValve.NoopDlsFlsRequestValve();
            auditLog = new NullAuditLog();
            privilegesInterceptor = new PrivilegesInterceptor(resolver, clusterService, localClient, threadPool);
        } else {
            dlsFlsValve = new DlsFlsValveImpl();
            auditLog = new AuditLogImpl(settings, configPath, localClient, threadPool, resolver, clusterService, environment);
            privilegesInterceptor = new PrivilegesInterceptorImpl(resolver, clusterService, localClient, threadPool);
        }

        sslExceptionHandler = new AuditLogSslExceptionHandler(auditLog);

        adminDns = new AdminDNs(settings);
        
        cr = ConfigurationRepository.create(settings, this.configPath, threadPool, localClient, clusterService, auditLog);

        final XFFResolver xffResolver = new XFFResolver(threadPool);
        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool);

        final CompatConfig compatConfig = new CompatConfig(environment, transportPassiveAuthSetting);

        // DLS-FLS is enabled if not client and not disabled and not SSL only.
        final boolean dlsFlsEnabled = !SSLConfig.isSslOnlyMode();
        evaluator = new PrivilegesEvaluator(clusterService, threadPool, cr, resolver, auditLog,
                settings, privilegesInterceptor, cih, irr, dlsFlsEnabled);

        sf = new SecurityFilter(localClient, settings, evaluator, adminDns, dlsFlsValve, auditLog, threadPool, cs, compatConfig, irr, backendRegistry);

        final String principalExtractorClass = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, null);

        if(principalExtractorClass == null) {
            principalExtractor = new DefaultPrincipalExtractor();
        } else {
            principalExtractor = ReflectionHelper.instantiatePrincipalExtractor(principalExtractorClass);
        }

        securityRestHandler = new SecurityRestFilter(backendRegistry, auditLog, threadPool,
                principalExtractor, settings, configPath, compatConfig);

        final DynamicConfigFactory dcf = new DynamicConfigFactory(cr, settings, configPath, localClient, threadPool, cih);
        dcf.registerDCFListener(backendRegistry);
        dcf.registerDCFListener(compatConfig);
        dcf.registerDCFListener(irr);
        dcf.registerDCFListener(xffResolver);
        dcf.registerDCFListener(evaluator);
        dcf.registerDCFListener(securityRestHandler);
        if (!(auditLog instanceof NullAuditLog)) {
            // Don't register if advanced modules is disabled in which case auditlog is instance of NullAuditLog
            dcf.registerDCFListener(auditLog);
        }

        cr.setDynamicConfigFactory(dcf);

        si = new SecurityInterceptor(settings, threadPool, backendRegistry, auditLog, principalExtractor,
                interClusterRequestEvaluator, cs, Objects.requireNonNull(sslExceptionHandler), Objects.requireNonNull(cih), SSLConfig);
        components.add(principalExtractor);

        // NOTE: We need to create DefaultInterClusterRequestEvaluator before creating ConfigurationRepository since the latter requires security index to be accessible which means
        // communciation with other nodes is already up. However for the communication to be up, there needs to be trusted nodes_dn. Hence the base values from opensearch.yml
        // is used to first establish trust between same cluster nodes and there after dynamic config is loaded if enabled.
        if (DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS.equals(className)) {
            DefaultInterClusterRequestEvaluator e = (DefaultInterClusterRequestEvaluator) interClusterRequestEvaluator;
            e.subscribeForChanges(dcf);
        }

        components.add(adminDns);
        components.add(cr);
        components.add(xffResolver);
        components.add(backendRegistry);
        components.add(evaluator);
        components.add(si);
        components.add(dcf);


        return components;

    }

    @Override
    public Settings additionalSettings() {

        if(disabled) {
            return Settings.EMPTY;
        }

        final Settings.Builder builder = Settings.builder();

        builder.put(super.additionalSettings());

        if(!SSLConfig.isSslOnlyMode()){
          builder.put(NetworkModule.TRANSPORT_TYPE_KEY, "org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport");
          builder.put(NetworkModule.HTTP_TYPE_KEY, "org.opensearch.security.http.SecurityHttpServerTransport");
        }
        return builder.build();
    }
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        settings.addAll(super.getSettings());
        
        settings.add(Setting.boolSetting(ConfigConstants.SECURITY_SSL_ONLY, false, Property.NodeScope, Property.Filtered));

        // currently dual mode is supported only when ssl_only is enabled, but this stance would change in future
        settings.add(SecuritySettings.SSL_DUAL_MODE_SETTING);
        settings.add(SecuritySettings.LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING);

        // Protected index settings
        settings.add(Setting.boolSetting(ConfigConstants.SECURITY_PROTECTED_INDICES_ENABLED_KEY, ConfigConstants.SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered, Property.Final));
        settings.add(Setting.listSetting(ConfigConstants.SECURITY_PROTECTED_INDICES_KEY, ConfigConstants.SECURITY_PROTECTED_INDICES_DEFAULT, Function.identity(), Property.NodeScope, Property.Filtered, Property.Final));
        settings.add(Setting.listSetting(ConfigConstants.SECURITY_PROTECTED_INDICES_ROLES_KEY, ConfigConstants.SECURITY_PROTECTED_INDICES_ROLES_DEFAULT, Function.identity(), Property.NodeScope, Property.Filtered, Property.Final));

        // System index settings
        settings.add(Setting.boolSetting(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered, Property.Final));
        settings.add(Setting.listSetting(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, ConfigConstants.SECURITY_SYSTEM_INDICES_DEFAULT, Function.identity(), Property.NodeScope, Property.Filtered, Property.Final));

        if(!SSLConfig.isSslOnlyMode()) {
            settings.add(Setting.listSetting(ConfigConstants.SECURITY_AUTHCZ_ADMIN_DN, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
    
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, Property.NodeScope, Property.Filtered));
            settings.add(Setting.groupSetting(ConfigConstants.SECURITY_AUTHCZ_IMPERSONATION_DN+".", Property.NodeScope)); //not filtered here
    
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_CERT_OID, Property.NodeScope, Property.Filtered));
    
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.SECURITY_NODES_DN, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here

            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, false, Property.NodeScope));//not filtered here
    
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, ConfigConstants.SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                    Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, ConfigConstants.SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                    Property.NodeScope, Property.Filtered));
    
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_DISABLED, false, Property.NodeScope, Property.Filtered));
    
            settings.add(Setting.intSetting(ConfigConstants.SECURITY_CACHE_TTL_MINUTES, 60, 0, Property.NodeScope, Property.Filtered));
    
            //Security
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_ADVANCED_MODULES_ENABLED, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.groupSetting(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".", Property.NodeScope)); //not filtered here
    
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_DISABLE_ENVVAR_REPLACEMENT, false, Property.NodeScope, Property.Filtered));
    
            // Security - Audit
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.groupSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_ROUTES + ".", Property.NodeScope));
            settings.add(Setting.groupSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_ENDPOINTS + ".",  Property.NodeScope));
            settings.add(Setting.intSetting(ConfigConstants.SECURITY_AUDIT_THREADPOOL_SIZE, 10, Property.NodeScope, Property.Filtered));
            settings.add(Setting.intSetting(ConfigConstants.SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, 100*1000, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true, Property.NodeScope, Property.Filtered));
            final List<String> disabledCategories = new ArrayList<String>(2);
            disabledCategories.add("AUTHENTICATED");
            disabledCategories.add("GRANTED_PRIVILEGES");
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, disabledCategories, Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, disabledCategories, Function.identity(), Property.NodeScope)); //not filtered here
            final List<String> ignoredUsers = new ArrayList<String>(2);
            ignoredUsers.add("kibanaserver");
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, ignoredUsers, Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true, Property.NodeScope, Property.Filtered));
    
            
            // Security - Audit - Sink
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_TYPE, Property.NodeScope, Property.Filtered));
    
            // External OpenSearch
            settings.add(Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS, Lists.newArrayList("localhost:9200"), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here
            settings.add(Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here
    
            // Webhooks
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_URL, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_FORMAT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, Property.NodeScope, Property.Filtered));
            
            // Log4j
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_LOG4J_LOGGER_NAME, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_LOG4J_LEVEL, Property.NodeScope, Property.Filtered));
            
    
            // Kerberos
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_KERBEROS_KRB5_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL, Property.NodeScope, Property.Filtered));
    
    
            // OpenSearch Security - REST API
            settings.add(Setting.listSetting(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.groupSetting(ConfigConstants.SECURITY_RESTAPI_ENDPOINTS_DISABLED + ".", Property.NodeScope));
            
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, Property.NodeScope, Property.Filtered));

            
            // Compliance
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.simpleString(ConfigConstants.SECURITY_COMPLIANCE_SALT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(transportPassiveAuthSetting.getDynamicSetting());

            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, false, Property.NodeScope,
                    Property.Filtered));

            //compat
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, false, Property.NodeScope, Property.Filtered));

            // system integration
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, false, Property.NodeScope, Property.Filtered));
        }
        
        return settings;
    }

    @Override
    public List<String> getSettingsFilter() {
        List<String> settingsFilter = new ArrayList<>();

        if(disabled) {
            return settingsFilter;
        }
        settingsFilter.add("opendistro_security.*");
        settingsFilter.add("plugins.security.*");
        return settingsFilter;
    }
    
    @Override
    public void onNodeStarted() {
        log.info("Node started");
        if(!SSLConfig.isSslOnlyMode() && !client && !disabled) {
            cr.initOnNodeStart();
        }
        final Set<ModuleInfo> securityModules = ReflectionHelper.getModulesLoaded();
        log.info("{} OpenSearch Security modules loaded so far: {}", securityModules.size(), securityModules);
    }

    //below is a hack because it seems not possible to access RepositoriesService from a non guice class
    //the way of how deguice is organized is really a mess - hope this can be fixed in later versions
    //TODO check if this could be removed

    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {

        if (client || disabled || SSLConfig.isSslOnlyMode()) {
            return Collections.emptyList();
        }

        final List<Class<? extends LifecycleComponent>> services = new ArrayList<>(1);
        services.add(GuiceHolder.class);
        return services;
    }

    @Override
    public Function<String, Predicate<String>> getFieldFilter() {
        return index -> {
            if (threadPool == null) {
                return field -> true;
            }
            final Map<String, Set<String>> allowedFlsFields = (Map<String, Set<String>>) HeaderHelper
                    .deserializeSafeFromHeader(threadPool.getThreadContext(), ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER);

            final String eval = SecurityUtils.evalMap(allowedFlsFields, index);

            if (eval == null) {
                return field -> true;
            } else {

                final Set<String> includesExcludes = allowedFlsFields.get(eval);
                final Set<String> includesSet = new HashSet<>(includesExcludes.size());
                final Set<String> excludesSet = new HashSet<>(includesExcludes.size());


                for (final String incExc : includesExcludes) {
                    final char firstChar = incExc.charAt(0);

                    if (firstChar == '!' || firstChar == '~') {
                        excludesSet.add(incExc.substring(1));
                    } else {
                        includesSet.add(incExc);
                    }
                }

                if (!excludesSet.isEmpty()) {
                    WildcardMatcher excludeMatcher = WildcardMatcher.from(excludesSet);
                    return field -> !excludeMatcher.test(handleKeyword(field));
                } else {
                    WildcardMatcher includeMatcher = WildcardMatcher.from(includesSet);
                    return field -> includeMatcher.test(handleKeyword(field));
                }
            }
        };
    }

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final String indexPattern = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(indexPattern, "Security index");
        return Collections.singletonList(systemIndexDescriptor);
    }

    private static String handleKeyword(final String field) {
        if(field != null && field.endsWith(KEYWORD)) {
            return field.substring(0, field.length()-KEYWORD.length());
        }
        return field;
    }

    public static class GuiceHolder implements LifecycleComponent {

        private static RepositoriesService repositoriesService;
        private static RemoteClusterService remoteClusterService;

        @Inject
        public GuiceHolder(final RepositoriesService repositoriesService,
                final TransportService remoteClusterService) {
            GuiceHolder.repositoriesService = repositoriesService;
            GuiceHolder.remoteClusterService = remoteClusterService.getRemoteClusterService();
        }

        public static RepositoriesService getRepositoriesService() {
            return repositoriesService;
        }

        public static RemoteClusterService getRemoteClusterService() {
            return remoteClusterService;
        }

        @Override
        public void close() {
        }

        @Override
        public State lifecycleState() {
            return null;
        }

        @Override
        public void addLifecycleListener(LifecycleListener listener) {
        }

        @Override
        public void removeLifecycleListener(LifecycleListener listener) {
        }

        @Override
        public void start() {
        }

        @Override
        public void stop() {
        }

    }
}
