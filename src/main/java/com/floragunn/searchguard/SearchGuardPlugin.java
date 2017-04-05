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

import com.floragunn.searchguard.support.ConfigConstants;

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
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportInterceptor;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.auditlog.AuditLogModule;
import com.floragunn.searchguard.configuration.BackendModule;
import com.floragunn.searchguard.configuration.ConfigurationModule;
import com.floragunn.searchguard.configuration.InterceptorModule;
import com.floragunn.searchguard.configuration.SearchGuardIndexSearcherWrapper;
import com.floragunn.searchguard.filter.SearchGuardFilter;
import com.floragunn.searchguard.http.SearchGuardHttpServerTransport;
import com.floragunn.searchguard.http.SearchGuardNonSslHttpServerTransport;
import com.floragunn.searchguard.rest.KibanaInfoAction;
import com.floragunn.searchguard.rest.SearchGuardInfoAction;
import com.floragunn.searchguard.ssl.DefaultSearchGuardKeyStore;
import com.floragunn.searchguard.ssl.ExternalSearchGuardKeyStore;
import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.SearchGuardSSLModule;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLNettyTransport;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ReflectionHelper;
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
    private final UUID instanceUUID = UUID.randomUUID();
    private final boolean dlsFlsAvailable;
    private final Constructor dlFlsConstructor;
    private final SearchGuardKeyStore sgks;
    
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
    
        if(ReflectionHelper.canLoad(FLS_DLS_INDEX_SEARCHER_WRAPPER_CLASS)) {
            try {
                dlFlsConstructor = ReflectionHelper
                .load(FLS_DLS_INDEX_SEARCHER_WRAPPER_CLASS)
                .getConstructor(IndexService.class, Settings .class);
            } catch (Exception e) {
                throw new RuntimeException("Failed to enable FLS/DLS", e);
            }

            dlsFlsAvailable = dlFlsConstructor != null;
            log.info("FLS/DLS module available");
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
                } catch(Exception ex) {
                    log.error("Failed to register SearchGuardRestApiActions, management API not available", ex);
                }
            }
        }
        return handlers;
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
        if (!client && !tribeNodeClient) {
            modules.add(new ConfigurationModule());
            modules.add(new BackendModule());
            modules.add(new AuditLogModule());
            modules.add(new InterceptorModule(instanceUUID.toString()));
        }
        
        return modules;
    }
    
    private IndexSearcherWrapper loadFlsDlsIndexSearcherWrapper(final IndexService indexService) {
        try {
            IndexSearcherWrapper flsdlsWrapper = (IndexSearcherWrapper) dlFlsConstructor.newInstance(indexService, settings);
            log.info("FLS/DLS enabled");
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
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        return Collections.emptyList();
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
    public List<TransportInterceptor> getTransportInterceptors() {
        List<TransportInterceptor> interceptors = new ArrayList<TransportInterceptor>(1);
        
        if (!client && !tribeNodeClient) {
            interceptors.add(new TransportInterceptor() {

                @Override
                public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(String action, String executor,
                        TransportRequestHandler<T> actualHandler) {
                    
                    return new TransportRequestHandler<T>() {

                        @Override
                        public void messageReceived(T request, TransportChannel channel, Task task) throws Exception {
                            SearchGuardInterceptor.getSearchGuardInterceptor(instanceUUID.toString()).getHandler(action, actualHandler).messageReceived(request, channel, task);
                        }

                        @Override
                        public void messageReceived(T request, TransportChannel channel) throws Exception {
                            SearchGuardInterceptor.getSearchGuardInterceptor(instanceUUID.toString()).getHandler(action, actualHandler).messageReceived(request, channel);
                        }
                    };
                    
                }

                @Override
                public AsyncSender interceptSender(AsyncSender sender) {
                    
                    return new AsyncSender() {
                        
                        @Override
                        public <T extends TransportResponse> void sendRequest(DiscoveryNode node, String action, TransportRequest request,
                                TransportRequestOptions options, TransportResponseHandler<T> handler) {
                            SearchGuardInterceptor.getSearchGuardInterceptor(instanceUUID.toString()).sendRequestDecorate(sender, node, action, request, options, handler);
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
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {

        Map<String, Supplier<HttpServerTransport>> httpTransports = new HashMap<String, Supplier<HttpServerTransport>>(1);
        if (!client && httpSSLEnabled && !tribeNodeClient) {
            httpTransports.put("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", 
                    () -> new SearchGuardHttpServerTransport(settings, networkService, bigArrays, threadPool, sgks, null));
        } else if (!client && !tribeNodeClient) {
            httpTransports.put("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", 
                    () -> new SearchGuardNonSslHttpServerTransport(settings, networkService, bigArrays, threadPool));
        }
        
        return httpTransports;
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
}
