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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.search.SearchRequestParsers;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
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
import com.floragunn.searchguard.auditlog.AuditLogModule;
import com.floragunn.searchguard.configuration.BackendModule;
import com.floragunn.searchguard.configuration.ConfigurationModule;
import com.floragunn.searchguard.configuration.InterceptorModule;
import com.floragunn.searchguard.configuration.SearchGuardIndexSearcherWrapper;
import com.floragunn.searchguard.filter.SearchGuardFilter;
import com.floragunn.searchguard.http.SearchGuardHttpServerTransport;
import com.floragunn.searchguard.rest.SearchGuardInfoAction;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLNettyTransport;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.transport.SearchGuardInterceptor;
import com.google.common.collect.Lists;

public final class SearchGuardPlugin extends Plugin implements ActionPlugin {

    private final Logger log = LogManager.getLogger(this.getClass());
    private static final String CLIENT_TYPE = "client.type";
    private final Settings settings;
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean tribeNodeClient;
    private final UUID instanceUUID = UUID.randomUUID();
    //private Holder<ThreadPool> threadPoolHolder = new Holder<ThreadPool>();

    public SearchGuardPlugin(final Settings settings) {
        super();
        if(!settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, true)) {
            throw new IllegalStateException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }
        
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        // initialize native netty open ssl libs
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

        if(client && System.getProperty("sg.nowarn.client") == null) {
            System.out.println("*************************************************************************");
            System.out.println("'Search Guard 2' plugin is normally not needed on transport client nodes.");
            System.out.println("*************************************************************************");
        }
    }
    
    @Override
    public List<Class<? extends RestHandler>> getRestHandlers() {
        List<Class<? extends RestHandler>> handlers = new ArrayList<Class<? extends RestHandler>>(1);
        if (!client && !tribeNodeClient) {
            handlers.add(SearchGuardInfoAction.class);
            handlers.add(SearchGuardSSLInfoAction.class);
        }
        return handlers;
    }
    
    @Override
    public List<ActionHandler<? extends ActionRequest<?>, ? extends ActionResponse>> getActions() {
        List<ActionHandler<? extends ActionRequest<?>, ? extends ActionResponse>> actions = new ArrayList<>(1);
        if(!tribeNodeClient) {
            actions.add(new ActionHandler(ConfigUpdateAction.INSTANCE, TransportConfigUpdateAction.class));
        }
        return actions;
    }
    
    
    @Override
    public Collection<Module> createGuiceModules() {
        List<Module> modules = new ArrayList<Module>(1);
        if (!client && !tribeNodeClient) {
            modules.add(new ConfigurationModule());
            modules.add(new BackendModule());
            modules.add(new AuditLogModule());
            modules.add(new InterceptorModule(instanceUUID.toString()));
        }
        
        return modules;
    }
    
    @Override
    public void onIndexModule(IndexModule indexModule) {
        //TODO include
        //com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper
        if (!client) {
            indexModule.setSearcherWrapper(indexService -> new SearchGuardIndexSearcherWrapper(indexService, settings));
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
    
    public void onModule(final NetworkModule module) {
        module.registerTransport("com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyTransport", SearchGuardSSLNettyTransport.class);

        if (!client && httpSSLEnabled && !tribeNodeClient) {
           System.out.println("register http");
            
            //module.registerHttpTransport("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", SearchGuardSSLNettyHttpServerTransport.class);
           module.registerHttpTransport("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", SearchGuardHttpServerTransport.class);
        }
        
        if (!client && !tribeNodeClient) {
            module.addTransportInterceptor(new TransportInterceptor() {

                @Override
                public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(String action,
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
    }
    
    
    @Override
    public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService, SearchRequestParsers searchRequestParsers) {
        //threadPoolHolder.setValue(threadPool);
        return super.createComponents(client, clusterService, threadPool, resourceWatcherService, scriptService, searchRequestParsers);
    }
        
    @Override
    public Settings additionalSettings() {
        final Settings.Builder builder = Settings.builder();
        
        builder.put(NetworkModule.TRANSPORT_TYPE_KEY, "com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyTransport");

        if (!client && !tribeNodeClient) {
            //builder.put(NetworkModule.TRANSPORT_SERVICE_TYPE_KEY, SearchGuardTransportService.class.toString());
            
            if (httpSSLEnabled) {
                builder.put(NetworkModule.HTTP_TYPE_KEY, "com.floragunn.searchguard.http.SearchGuardHttpServerTransport");
            }
        }

        return builder.build();
    }
    
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        settings.add(Setting.listSetting("searchguard.authcz.admin_dn", Collections.emptyList(), Function.identity(), Property.NodeScope));
        
        settings.add(Setting.groupSetting("searchguard.authcz.impersonation_dn.", Property.NodeScope));
        
        settings.add(Setting.simpleString("searchguard.audit.type", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.index", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.type", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.username", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.password", Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.simpleString("searchguard.kerberos.krb5_filepath", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.kerberos.acceptor_keytab_filepath", Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.listSetting("searchguard.audit.config.http_endpoints", Lists.newArrayList("localhost:9200"), Function.identity(), Property.NodeScope));
 
        settings.add(Setting.boolSetting("searchguard.audit.config.enable_ssl", false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.config.verify_hostnames", true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.config.enable_ssl_client_auth", false, Property.NodeScope, Property.Filtered));
        
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
        
        settings.add(Setting.simpleString("node.client", Property.NodeScope));
        settings.add(Setting.simpleString("node.local", Property.NodeScope));
                
        return settings;
    }

    
}
