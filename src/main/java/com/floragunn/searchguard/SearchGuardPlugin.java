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

package com.floragunn.searchguard;

import io.netty.handler.ssl.OpenSsl;
import io.netty.util.internal.PlatformDependent;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.Lifecycle.State;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.inject.util.Providers;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.search.SearchRequestParsers;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.Transport.Connection;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportInterceptor;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;
import org.elasticsearch.watcher.ResourceWatcherService;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.NullAuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;
import com.floragunn.searchguard.configuration.ActionGroupHolder;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.configuration.DlsFlsRequestValve;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.configuration.PrivilegesInterceptor;
import com.floragunn.searchguard.configuration.SearchGuardIndexSearcherWrapper;
import com.floragunn.searchguard.filter.SearchGuardFilter;
import com.floragunn.searchguard.filter.SearchGuardRestFilter;
import com.floragunn.searchguard.http.SearchGuardHttpServerTransport;
import com.floragunn.searchguard.http.SearchGuardNonSslHttpServerTransport;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.rest.KibanaInfoAction;
import com.floragunn.searchguard.rest.SearchGuardInfoAction;
import com.floragunn.searchguard.ssl.DefaultSearchGuardKeyStore;
import com.floragunn.searchguard.ssl.ExternalSearchGuardKeyStore;
import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.SearchGuardSSLModule;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.transport.DefaultPrincipalExtractor;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLNettyTransport;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.ReflectionHelper;
import com.floragunn.searchguard.transport.DefaultInterClusterRequestEvaluator;
import com.floragunn.searchguard.transport.InterClusterRequestEvaluator;
import com.floragunn.searchguard.transport.SearchGuardInterceptor;
import com.google.common.collect.Lists;

public final class SearchGuardPlugin extends Plugin implements ActionPlugin, NetworkPlugin {

    private static final String FLS_DLS_INDEX_SEARCHER_WRAPPER_CLASS = "com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper";
    private final Logger log = LogManager.getLogger(this.getClass());
    private static final String CLIENT_TYPE = "client.type";
    private final Settings settings;
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean tribeNodeClient;
    private final boolean dlsFlsAvailable;
    private final Constructor dlFlsConstructor;
    private final SearchGuardKeyStore sgks;
    private SearchGuardRestFilter sgRestHandler;
    private SearchGuardInterceptor sgi;
    
    //TODO 5mg check tribe
    public SearchGuardPlugin(final Settings settings) {
        super();
        log.info("Clustername: {}", settings.get("cluster.name","elasticsearch"));
        if(!settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, true)) {
            throw new IllegalStateException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }
        
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        //TODO check initialize native netty open ssl libs still necessary
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                PlatformDependent.newFixedMpscQueue(1);
                OpenSsl.isAvailable();
                return null;
            }
        });
        
        this.settings = settings;
        client = !"node".equals(this.settings.get(CLIENT_TYPE, "node"));
        boolean tribeNode = this.settings.getAsBoolean("action.master.force_local", false) && this.settings.getByPrefix("tribe").getAsMap().size() > 0;
        tribeNodeClient = this.settings.get("tribe.name", null) != null;
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT);

        //TODO tribe 5.0
        log.info("Node [{}] is a transportClient: {}/tribeNode: {}/tribeNodeClient: {}", settings.get("node.name"), client, tribeNode, tribeNodeClient);
    
        if(!client && ReflectionHelper.canLoad(FLS_DLS_INDEX_SEARCHER_WRAPPER_CLASS)) {
            try {
                dlFlsConstructor = ReflectionHelper
                .load(FLS_DLS_INDEX_SEARCHER_WRAPPER_CLASS)
                .getConstructor(IndexService.class, Settings .class);
            } catch (Exception e) {
                throw new RuntimeException("Failed to enable FLS/DLS", e);
            }

            dlsFlsAvailable = dlFlsConstructor != null;
            log.info("FLS/DLS module available: "+dlsFlsAvailable);
        } else {
            dlsFlsAvailable = false;
            dlFlsConstructor = null;
            log.info("FLS/DLS module not available");
        }
        
        if(ExternalSearchGuardKeyStore.hasExternalSslContext(settings)) {
            this.sgks = new ExternalSearchGuardKeyStore(settings);
        } else {
            this.sgks = new DefaultSearchGuardKeyStore(settings);
        }
    }
    
    @Override
    public List<Class<? extends RestHandler>> getRestHandlers() {
        List<Class<? extends RestHandler>> handlers = new ArrayList<Class<? extends RestHandler>>(1);
        if (!client && !tribeNodeClient) {
            handlers.add(SearchGuardInfoAction.class);
            handlers.add(KibanaInfoAction.class);
            handlers.add(SearchGuardSSLInfoAction.class);
            
            if(ReflectionHelper.canLoad("com.floragunn.searchguard.dlic.rest.api.SearchGuardRestApiActions")) {
                try {
                    Collection<Class<? extends RestHandler>> apiHandler = (Collection<Class<? extends RestHandler>>) ReflectionHelper
                    .load("com.floragunn.searchguard.dlic.rest.api.SearchGuardRestApiActions")
                    .getDeclaredMethod("getHandler")
                    .invoke(null);          
                    handlers.addAll(apiHandler);
                    log.debug("Added {} management rest handler", apiHandler.size());
                } catch(Throwable ex) {
                    log.error("Failed to register SearchGuardRestApiActions, management API not available", ex);
                }
            }
        }
        return handlers;
    }
    
    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(final ThreadContext threadContext) {
        return (rh) -> sgRestHandler.wrap(rh);
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> actions = new ArrayList<>(1);
        if(!tribeNodeClient) {
            actions.add(new ActionHandler(ConfigUpdateAction.INSTANCE, TransportConfigUpdateAction.class));
        }
        return actions;
    }
    
    @Override
    public Collection<Module> createGuiceModules() {
        List<Module> modules = new ArrayList<Module>(1);
        modules.add(new SearchGuardSSLModule(settings, sgks));
        return modules;
    }
    
    private IndexSearcherWrapper loadFlsDlsIndexSearcherWrapper(final IndexService indexService) {
        try {
            IndexSearcherWrapper flsdlsWrapper = (IndexSearcherWrapper) dlFlsConstructor.newInstance(indexService, settings);
            if(log.isDebugEnabled()) {
                log.debug("FLS/DLS enabled for index {}", indexService.index().getName());
            }
            return flsdlsWrapper;
        } catch(Exception ex) {
            throw new RuntimeException("Failed to enable FLS/DLS", ex);
        }
    }
    
    @Override
    public void onIndexModule(IndexModule indexModule) {
        //called for every index!
        
        if (!client) {
            if(dlsFlsAvailable) {
                indexModule.setSearcherWrapper(indexService -> loadFlsDlsIndexSearcherWrapper(indexService));
            } else {
                indexModule.setSearcherWrapper(indexService -> new SearchGuardIndexSearcherWrapper(indexService, settings));
            }
        }
    }
    
    @Override
    public List<Class<? extends ActionFilter>> getActionFilters() {
        List<Class<? extends ActionFilter>> filters = new ArrayList<>(1);
        if (!tribeNodeClient && !client) {
            filters.add(SearchGuardFilter.class);
        }
        return filters;
    }

    
    @Override
    public List<TransportInterceptor> getTransportInterceptors(ThreadContext threadContext) {
        List<TransportInterceptor> interceptors = new ArrayList<TransportInterceptor>(1);
        
        if (!client && !tribeNodeClient) {
            interceptors.add(new TransportInterceptor() {

                @Override
                public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(String action, String executor,
                        boolean forceExecution, TransportRequestHandler<T> actualHandler) {
                    
                    return new TransportRequestHandler<T>() {

                        @Override
                        public void messageReceived(T request, TransportChannel channel, Task task) throws Exception {
                            sgi.getHandler(action, actualHandler).messageReceived(request, channel, task);
                        }

                        @Override
                        public void messageReceived(T request, TransportChannel channel) throws Exception {
                            sgi.getHandler(action, actualHandler).messageReceived(request, channel);
                        }
                    };
                    
                }

                @Override
                public AsyncSender interceptSender(AsyncSender sender) {
                    
                    return new AsyncSender() {

                        @Override
                        public <T extends TransportResponse> void sendRequest(Connection connection, String action,
                                TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {
                            sgi.sendRequestDecorate(sender, connection, action, request, options, handler);
                            //SearchGuardInterceptor.getSearchGuardInterceptor(instanceUUID.toString()).sendRequestDecorate(sender, connection, action, request, options, handler);
                        }
                    };
                }
            });
        }
        
        return interceptors;
    }
    
    @Override
    public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {

        Map<String, Supplier<Transport>> transports = new HashMap<String, Supplier<Transport>>();
        transports.put("com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyTransport", 
                () -> new SearchGuardSSLNettyTransport(settings, threadPool, networkService, bigArrays, namedWriteableRegistry, circuitBreakerService, sgks));
 
        return transports;

    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry,
            NamedXContentRegistry xContentRegistry, NetworkService networkService) {
        Map<String, Supplier<HttpServerTransport>> httpTransports = new HashMap<String, Supplier<HttpServerTransport>>(1);
        if (!client && httpSSLEnabled && !tribeNodeClient) {
            httpTransports.put("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", 
                    () -> new SearchGuardHttpServerTransport(settings, networkService, bigArrays, threadPool, sgks, null, xContentRegistry));
        } else if (!client && !tribeNodeClient) {
            httpTransports.put("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", 
                    () -> new SearchGuardNonSslHttpServerTransport(settings, networkService, bigArrays, threadPool, xContentRegistry));
        }
        
        return httpTransports;
    }
    
    
        
    @Override
    public Collection<Object> createComponents(Client localClient, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService, SearchRequestParsers searchRequestParsers,
            NamedXContentRegistry xContentRegistry) {
        
        final List<Object> components = new ArrayList<Object>();
        
        if (client || tribeNodeClient) {
            return components;
        }
        
        
        DlsFlsRequestValve dlsFlsValve = new DlsFlsRequestValve.NoopDlsFlsRequestValve();
        
        try {
            Class<?> dlsFlsRequestValveClass;
            if ((dlsFlsRequestValveClass = Class.forName("com.floragunn.searchguard.configuration.DlsFlsValveImpl")) != null) {                                                                                                                           
                dlsFlsValve = (DlsFlsRequestValve) dlsFlsRequestValveClass.newInstance(); //zero args constructor
                log.info("FLS/DLS valve bound");
            } 
        } catch (Throwable e) {
            log.info("FLS/DLS valve not bound (noop) due to "+e);
        }
        
        final IndexNameExpressionResolver resolver = new IndexNameExpressionResolver(settings);
        AuditLog auditLog = new NullAuditLog();

        try {

            // @Inject
            // public AuditLogImpl(final Settings settings, Provider<Client>
            // clientProvider, ThreadPool threadPool,
            // final IndexNameExpressionResolver resolver, final
            // Provider<ClusterService> clusterService) {

            Class auditLogImplClass;
            if ((auditLogImplClass = Class.forName("com.floragunn.searchguard.auditlog.impl.AuditLogImpl")) != null) {
                auditLog = (AuditLog) auditLogImplClass.getConstructor(Settings.class, Provider.class , ThreadPool.class, IndexNameExpressionResolver.class, Provider.class)
                        .newInstance(settings, Providers.of(localClient), threadPool, resolver, Providers.of(clusterService));
                log.info("Auditlog available ({})", auditLogImplClass.getSimpleName());
            } 
        } catch (Throwable e) {
            log.info("Auditlog not available due to "+e);
        }
        
        final String DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = DefaultInterClusterRequestEvaluator.class.getName();
        InterClusterRequestEvaluator interClusterRequestEvaluator = new DefaultInterClusterRequestEvaluator(settings);

     
        final String className = settings.get(ConfigConstants.SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS);
        log.debug("Using {} as intercluster request evaluator class", className);
        if (!DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS.equals(className)) {
            try {
                final Class<?> klass = Class.forName(className);
                final Constructor<?> constructor = klass.getConstructor(Settings.class);
                interClusterRequestEvaluator = (InterClusterRequestEvaluator) constructor.newInstance(settings);
            } catch (Throwable e) {
                log.error("Using DefaultInterClusterRequestEvaluator. Unable to instantiate {} ", e, className);
                if (log.isTraceEnabled()) {
                    log.trace("Unable to instantiate InterClusterRequestEvaluator", e);
                }
            }
        }
        
        PrivilegesInterceptor privilegesInterceptor = new PrivilegesInterceptor(resolver, clusterService, localClient, threadPool);
        
        try {
            Class privilegesInterceptorImplClass;
            if ((privilegesInterceptorImplClass = Class
                    .forName("com.floragunn.searchguard.configuration.PrivilegesInterceptorImpl")) != null) {
                privilegesInterceptor = (PrivilegesInterceptor) privilegesInterceptorImplClass
                        .getConstructor(IndexNameExpressionResolver.class, ClusterService.class, Client.class, ThreadPool.class)
                        .newInstance(resolver, clusterService, localClient, threadPool);
                log.info("Privileges interceptor bound");
            }
        } catch (Throwable e) {
            log.info("Privileges interceptor not bound (noop) due to "+e);
        }

        
        
        final AdminDNs adminDns = new AdminDNs(settings);      
        final PrincipalExtractor pe = new DefaultPrincipalExtractor();        
        final ConfigurationRepository cr = IndexBaseConfigurationRepository.create(settings, threadPool, localClient, clusterService);        
        final InternalAuthenticationBackend iab = new InternalAuthenticationBackend(cr);     
        final XFFResolver xffResolver = new XFFResolver(threadPool);
        cr.subscribeOnChange(ConfigConstants.CONFIGNAME_CONFIG, xffResolver);   
        final BackendRegistry backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, iab, auditLog, threadPool);
        cr.subscribeOnChange(ConfigConstants.CONFIGNAME_CONFIG, backendRegistry); 
        final ActionGroupHolder ah = new ActionGroupHolder(cr); 

        final PrivilegesEvaluator pre = new PrivilegesEvaluator(clusterService, threadPool, cr, ah, resolver, auditLog, settings, privilegesInterceptor);    
        final SearchGuardFilter sgf = new SearchGuardFilter(settings, pre, adminDns, dlsFlsValve, auditLog, threadPool);     
        sgi = new SearchGuardInterceptor(settings, threadPool, backendRegistry, auditLog, pe, interClusterRequestEvaluator);
        
        components.add(adminDns);
        //components.add(auditLog);
        components.add(cr);
        components.add(iab);
        components.add(xffResolver);
        components.add(backendRegistry);
        components.add(ah);
        components.add(pre);
        components.add(sgf);
        components.add(sgi);

        sgRestHandler = new SearchGuardRestFilter(backendRegistry, auditLog, threadPool, pe, settings);
        
        return components;
        
    }

    @Override
    public Settings additionalSettings() {
        final Settings.Builder builder = Settings.builder();
        builder.put(NetworkModule.TRANSPORT_TYPE_KEY, "com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyTransport");
        builder.put(NetworkModule.HTTP_TYPE_KEY, "com.floragunn.searchguard.http.SearchGuardHttpServerTransport");
        return builder.build();
    }
    
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        settings.add(Setting.listSetting("searchguard.authcz.admin_dn", Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here

        settings.add(Setting.simpleString("searchguard.config_index_name", Property.NodeScope, Property.Filtered));
        settings.add(Setting.groupSetting("searchguard.authcz.impersonation_dn.", Property.NodeScope)); //not filtered here

        settings.add(Setting.simpleString("searchguard.audit.type", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.index", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.type", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.username", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.password", Property.NodeScope, Property.Filtered));
        settings.add(Setting.listSetting("searchguard.audit.config.disabled_categories", Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
        settings.add(Setting.intSetting("searchguard.audit.threadpool.size", 10, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.enable_request_details", false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.config.webhook.ssl.verify", true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.webhook.url", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.webhook.format", Property.NodeScope, Property.Filtered));
        
        
        settings.add(Setting.simpleString("searchguard.kerberos.krb5_filepath", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.kerberos.acceptor_keytab_filepath", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.kerberos.acceptor_principal", Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.listSetting("searchguard.audit.config.http_endpoints", Lists.newArrayList("localhost:9200"), Function.identity(), Property.NodeScope)); //not filtered here
        settings.add(Setting.boolSetting("searchguard.audit.config.enable_ssl", false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.config.verify_hostnames", true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.config.enable_ssl_client_auth", false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.webhook_url", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.webhook_format", Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString("searchguard.cert.oid", Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString("searchguard.cert.intercluster_request_evaluator_class", Property.NodeScope, Property.Filtered));
        settings.add(Setting.listSetting("searchguard.nodes_dn", Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here

        settings.add(Setting.boolSetting(ConfigConstants.SG_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, ConfigConstants.SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SG_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, ConfigConstants.SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                Property.NodeScope, Property.Filtered));

        //SSL
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED, SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true,Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_CIPHERS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_PROTOCOLS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_CIPHERS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_PROTOCOLS, Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_CLIENT_EXTERNAL_CONTEXT_ID, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMKEY_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CRL_FILE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CRL_VALIDATE, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CRL_DISABLE_CRLDP, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CRL_DISABLE_OCSP, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.longSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CRL_VALIDATION_DATE, -1, -1, Property.NodeScope, Property.Filtered));

        settings.add(Setting.listSetting("searchguard.audit.ignore_users", Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here

        settings.add(Setting.simpleString("node.client", Property.NodeScope));
        settings.add(Setting.simpleString("node.local", Property.NodeScope));
    
        return settings;
    }
    
    @Override
    public List<String> getSettingsFilter() {
        List<String> settingsFilter = new ArrayList<>();
        settingsFilter.add("searchguard.*");
        return settingsFilter;
    }

    //below is a hack because it seems not possible to access RepositoriesService from a non guice class
    //the way of how deguice is organized is really a mess - hope this can be fixed in later versions
    //TODO check if this could be removed
    
    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {

        if (client || tribeNodeClient) {
            return Collections.emptyList();
        }
        
        final List<Class<? extends LifecycleComponent>> services = new ArrayList<>(1);
        services.add(RepositoriesServiceHolder.class);
        return services;
    }
    
    public static class RepositoriesServiceHolder implements LifecycleComponent {

        private static RepositoriesService repositoriesService;
        
        @Inject
        public RepositoriesServiceHolder(final RepositoriesService repositoriesService) {
            RepositoriesServiceHolder.repositoriesService = repositoriesService;
        }

        public static RepositoriesService getRepositoriesService() {
            return repositoriesService;
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
