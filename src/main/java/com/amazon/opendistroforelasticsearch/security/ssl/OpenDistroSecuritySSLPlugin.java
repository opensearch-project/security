/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.amazon.opendistroforelasticsearch.security.ssl;

import io.netty.handler.ssl.OpenSsl;
import io.netty.util.internal.PlatformDependent;

import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.Version;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Booleans;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsFilter;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.http.HttpServerTransport.Dispatcher;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportInterceptor;
import org.elasticsearch.watcher.ResourceWatcherService;

import com.amazon.opendistroforelasticsearch.security.ssl.http.netty.OpenDistroSecuritySSLNettyHttpServerTransport;
import com.amazon.opendistroforelasticsearch.security.ssl.http.netty.ValidatingDispatcher;
import com.amazon.opendistroforelasticsearch.security.ssl.rest.OpenDistroSecuritySSLInfoAction;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.OpenDistroSecuritySSLNettyTransport;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.OpenDistroSecuritySSLTransportInterceptor;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;

//For ES5 this class has only effect when SSL only plugin is installed
public class OpenDistroSecuritySSLPlugin extends Plugin implements ActionPlugin, NetworkPlugin {

    private static boolean USE_NETTY_DEFAULT_ALLOCATOR = Booleans.parseBoolean(System.getProperty("es.unsafe.use_netty_default_allocator"), false);
    public static final boolean OPENSSL_SUPPORTED = (PlatformDependent.javaVersion() < 12) && USE_NETTY_DEFAULT_ALLOCATOR;
    protected final Logger log = LogManager.getLogger(this.getClass());
    protected static final String CLIENT_TYPE = "client.type";
    protected final boolean client;
    protected final boolean httpSSLEnabled;
    protected final boolean transportSSLEnabled;
    protected final Settings settings;
    protected final OpenDistroSecurityKeyStore odsks;
    protected PrincipalExtractor principalExtractor;
    protected final Path configPath;
    private final static SslExceptionHandler NOOP_SSL_EXCEPTION_HANDLER = new SslExceptionHandler() {};
    
//    public OpenDistroSecuritySSLPlugin(final Settings settings, final Path configPath) {
//        this(settings, configPath, false);
//    }

    protected OpenDistroSecuritySSLPlugin(final Settings settings, final Path configPath, boolean disabled) {
     
        if(disabled) {
            this.settings = null;
            this.client = false;
            this.httpSSLEnabled = false;
            this.transportSSLEnabled = false;
            this.odsks = null;
            this.configPath = null;
            
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                @Override
                public Object run() {
                    System.setProperty("es.set.netty.runtime.available.processors", "false");
                    return null;
                }
            });
            
            
            return;
        }
        
        this.configPath = configPath;
        
        if(this.configPath != null) {
            log.info("ES Config path is "+this.configPath.toAbsolutePath());
        } else {
            log.info("ES Config path is not set");
        }
        
        final boolean allowClientInitiatedRenegotiation = settings.getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_ALLOW_CLIENT_INITIATED_RENEGOTIATION, false);
        final boolean rejectClientInitiatedRenegotiation = Boolean.parseBoolean(System.getProperty(SSLConfigConstants.JDK_TLS_REJECT_CLIENT_INITIATED_RENEGOTIATION));
   
        if(allowClientInitiatedRenegotiation && !rejectClientInitiatedRenegotiation) {
            final String renegoMsg = "Client side initiated TLS renegotiation enabled. This can open a vulnerablity for DoS attacks through client side initiated TLS renegotiation.";
            log.warn(renegoMsg);
            System.out.println(renegoMsg);
            System.err.println(renegoMsg);
        } else {   
            if(!rejectClientInitiatedRenegotiation) {
                
                final SecurityManager sm = System.getSecurityManager();

                if (sm != null) {
                    sm.checkPermission(new SpecialPermission());
                }
                
                AccessController.doPrivileged(new PrivilegedAction<Object>() {
                    @Override
                    public Object run() {
                        System.setProperty(SSLConfigConstants.JDK_TLS_REJECT_CLIENT_INITIATED_RENEGOTIATION, "true");
                        return null;
                    }
                });
                log.debug("Client side initiated TLS renegotiation forcibly disabled. This can prevent DoS attacks. (jdk.tls.rejectClientInitiatedRenegotiation set to true).");
            } else {
                log.debug("Client side initiated TLS renegotiation already disabled.");
            }
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        //TODO check initialize native netty open ssl libs still neccessary
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                System.setProperty("es.set.netty.runtime.available.processors", "false");
                PlatformDependent.newFixedMpscQueue(1);
                OpenSsl.isAvailable();
                return null;
            }
        });

        this.settings = settings;
        client = !"node".equals(this.settings.get(OpenDistroSecuritySSLPlugin.CLIENT_TYPE));
        
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED,
                SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_DEFAULT);
        transportSSLEnabled = settings.getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED,
                SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT);

        if (!httpSSLEnabled && !transportSSLEnabled) {
            log.error("SSL not activated for http and/or transport.");
            System.out.println("SSL not activated for http and/or transport.");
            System.err.println("SSL not activated for http and/or transport.");
        }
        
        if(ExternalOpenDistroSecurityKeyStore.hasExternalSslContext(settings)) {
            this.odsks = new ExternalOpenDistroSecurityKeyStore(settings);
        } else {
            this.odsks = new DefaultOpenDistroSecurityKeyStore(settings, configPath);
        }
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            PageCacheRecycler pageCacheRecycler, CircuitBreakerService circuitBreakerService, NamedXContentRegistry xContentRegistry,
            NetworkService networkService, Dispatcher dispatcher, ClusterSettings clusterSettings) {
        
        if (!client && httpSSLEnabled) {
            
            final ValidatingDispatcher validatingDispatcher = new ValidatingDispatcher(threadPool.getThreadContext(), dispatcher, settings, configPath, NOOP_SSL_EXCEPTION_HANDLER);
            final OpenDistroSecuritySSLNettyHttpServerTransport sgsnht = new OpenDistroSecuritySSLNettyHttpServerTransport(settings, networkService, bigArrays, threadPool, odsks, xContentRegistry, validatingDispatcher, NOOP_SSL_EXCEPTION_HANDLER, clusterSettings);

            return Collections.singletonMap("com.amazon.opendistroforelasticsearch.security.ssl.http.netty.OpenDistroSecuritySSLNettyHttpServerTransport", () -> sgsnht);
            
        }
        return Collections.emptyMap();

    }

    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {
        
        final List<RestHandler> handlers = new ArrayList<RestHandler>(1);
        
        if (!client) {
            handlers.add(new OpenDistroSecuritySSLInfoAction(settings, configPath, restController, odsks, Objects.requireNonNull(principalExtractor)));
        }
        
        return handlers;
    }
    
    
    
    @Override
    public List<TransportInterceptor> getTransportInterceptors(NamedWriteableRegistry namedWriteableRegistry, ThreadContext threadContext) {
        List<TransportInterceptor> interceptors = new ArrayList<TransportInterceptor>(1);
        
        if(transportSSLEnabled && !client) {
            interceptors.add(new OpenDistroSecuritySSLTransportInterceptor(settings, null, null, NOOP_SSL_EXCEPTION_HANDLER));
        }
        
        return interceptors;
    }

    
    
    @Override
    public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, PageCacheRecycler pageCacheRecycler,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {
        
        Map<String, Supplier<Transport>> transports = new HashMap<String, Supplier<Transport>>();
        if (transportSSLEnabled) {
            transports.put("com.amazon.opendistroforelasticsearch.security.ssl.http.netty.OpenDistroSecuritySSLNettyTransport",
                    () -> new OpenDistroSecuritySSLNettyTransport(settings, Version.CURRENT, threadPool, networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService, odsks, NOOP_SSL_EXCEPTION_HANDLER));

        }
        return transports;

    }
    
    @Override
    public Collection<Object> createComponents(Client localClient, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry,
            Environment environment, NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry, IndexNameExpressionResolver indexNameExpressionResolver) {

        final List<Object> components = new ArrayList<>(1);
        
        if(client) {
            return components;
        }
        
        final String principalExtractorClass = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, null);

        if(principalExtractorClass == null) {
            principalExtractor = new com.amazon.opendistroforelasticsearch.security.ssl.transport.DefaultPrincipalExtractor();
        } else {
            try {
                log.debug("Try to load and instantiate '{}'", principalExtractorClass);
                Class<?> principalExtractorClazz = Class.forName(principalExtractorClass);
                principalExtractor = (PrincipalExtractor) principalExtractorClazz.newInstance();
            } catch (Exception e) {
                log.error("Unable to load '{}' due to", principalExtractorClass, e);
                throw new ElasticsearchException(e);
            }
        }
        
        components.add(principalExtractor);
        
        return components;
    }

    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, OPENSSL_SUPPORTED, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED, SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, OPENSSL_SUPPORTED,Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED, SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.listSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_CIPHERS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here
        settings.add(Setting.listSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here
        settings.add(Setting.listSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here
        settings.add(Setting.listSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_FILE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_VALIDATE, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.longSetting(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, -1, -1, Property.NodeScope, Property.Filtered));
        return settings;
    }


    @Override
    public Settings additionalSettings() {
       final Settings.Builder builder = Settings.builder();
        
       if(!client && httpSSLEnabled) {
           
           if(settings.get("http.compression") == null) {
               builder.put("http.compression", false);
               log.info("Disabled https compression by default to mitigate BREACH attacks. You can enable it by setting 'http.compression: true' in elasticsearch.yml");
           }
           
           builder.put(NetworkModule.HTTP_TYPE_KEY, "com.amazon.opendistroforelasticsearch.security.ssl.http.netty.OpenDistroSecuritySSLNettyHttpServerTransport");
       }
        
       if (transportSSLEnabled) {
           builder.put(NetworkModule.TRANSPORT_TYPE_KEY, "com.amazon.opendistroforelasticsearch.security.ssl.http.netty.OpenDistroSecuritySSLNettyTransport");
       }
        
        return builder.build();
    }
    
    @Override
    public List<String> getSettingsFilter() {
        List<String> settingsFilter = new ArrayList<>();
        settingsFilter.add("opendistro_security.*");
        return settingsFilter;
    }
}
