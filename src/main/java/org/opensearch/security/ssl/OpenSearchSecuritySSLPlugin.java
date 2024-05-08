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

package org.opensearch.security.ssl;

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
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

import com.fasterxml.jackson.databind.InjectableValues;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.Version;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Booleans;
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
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.indices.breaker.CircuitBreakerService;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.http.HttpServerTransport;
import org.opensearch.http.HttpServerTransport.Dispatcher;
import org.opensearch.http.netty4.ssl.SecureNetty4HttpServerTransport;
import org.opensearch.plugins.NetworkPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SecureHttpTransportSettingsProvider;
import org.opensearch.plugins.SecureSettingsFactory;
import org.opensearch.plugins.SecureTransportSettingsProvider;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.NonValidatingObjectMapper;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.ssl.http.netty.ValidatingDispatcher;
import org.opensearch.security.ssl.rest.SecuritySSLInfoAction;
import org.opensearch.security.ssl.transport.DefaultPrincipalExtractor;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.ssl.transport.SecuritySSLTransportInterceptor;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.telemetry.tracing.Tracer;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;
import org.opensearch.transport.Transport;
import org.opensearch.transport.TransportInterceptor;
import org.opensearch.transport.netty4.ssl.SecureNetty4Transport;
import org.opensearch.watcher.ResourceWatcherService;

import io.netty.handler.ssl.OpenSsl;
import io.netty.util.internal.PlatformDependent;

//For ES5 this class has only effect when SSL only plugin is installed
public class OpenSearchSecuritySSLPlugin extends Plugin implements SystemIndexPlugin, NetworkPlugin {
    private static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION = Setting.boolSetting(
        SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION,
        true,
        Property.NodeScope,
        Property.Filtered,
        Property.Deprecated
    );

    private static final Setting<Boolean> SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = Setting.boolSetting(
        SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME,
        true,
        Property.NodeScope,
        Property.Filtered,
        Property.Deprecated
    );

    private static boolean USE_NETTY_DEFAULT_ALLOCATOR = Booleans.parseBoolean(
        System.getProperty("opensearch.unsafe.use_netty_default_allocator"),
        false
    );
    public static final boolean OPENSSL_SUPPORTED = (PlatformDependent.javaVersion() < 12) && USE_NETTY_DEFAULT_ALLOCATOR;
    protected final Logger log = LogManager.getLogger(this.getClass());
    public static final String CLIENT_TYPE = "client.type";
    protected final boolean client;
    protected final boolean httpSSLEnabled;
    protected final boolean transportSSLEnabled;
    protected final boolean extendedKeyUsageEnabled;
    protected final Settings settings;
    protected volatile SecurityRestFilter securityRestHandler;
    protected final SharedGroupFactory sharedGroupFactory;
    protected final SecurityKeyStore sks;
    protected PrincipalExtractor principalExtractor;
    protected final Path configPath;
    private final static SslExceptionHandler NOOP_SSL_EXCEPTION_HANDLER = new SslExceptionHandler() {
    };
    protected final SSLConfig SSLConfig;
    protected volatile ThreadPool threadPool;

    @SuppressWarnings("removal")
    protected OpenSearchSecuritySSLPlugin(final Settings settings, final Path configPath, boolean disabled) {

        if (disabled) {
            this.settings = null;
            this.sharedGroupFactory = null;
            this.client = false;
            this.httpSSLEnabled = false;
            this.transportSSLEnabled = false;
            this.extendedKeyUsageEnabled = false;
            this.sks = null;
            this.configPath = null;
            SSLConfig = new SSLConfig(false, false);

            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                @Override
                public Object run() {
                    System.setProperty("opensearch.set.netty.runtime.available.processors", "false");
                    return null;
                }
            });

            return;
        }
        SSLConfig = new SSLConfig(settings);
        this.configPath = configPath;

        if (this.configPath != null) {
            log.info("OpenSearch Config path is {}", this.configPath.toAbsolutePath());
        } else {
            log.info("OpenSearch Config path is not set");
        }

        final boolean allowClientInitiatedRenegotiation = settings.getAsBoolean(
            SSLConfigConstants.SECURITY_SSL_ALLOW_CLIENT_INITIATED_RENEGOTIATION,
            false
        );
        final boolean rejectClientInitiatedRenegotiation = Boolean.parseBoolean(
            System.getProperty(SSLConfigConstants.JDK_TLS_REJECT_CLIENT_INITIATED_RENEGOTIATION)
        );

        if (allowClientInitiatedRenegotiation && !rejectClientInitiatedRenegotiation) {
            final String renegoMsg =
                "Client side initiated TLS renegotiation enabled. This can open a vulnerablity for DoS attacks through client side initiated TLS renegotiation.";
            log.warn(renegoMsg);
        } else {
            if (!rejectClientInitiatedRenegotiation) {

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
                log.debug(
                    "Client side initiated TLS renegotiation forcibly disabled. This can prevent DoS attacks. (jdk.tls.rejectClientInitiatedRenegotiation set to true)."
                );
            } else {
                log.debug("Client side initiated TLS renegotiation already disabled.");
            }
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        // TODO check initialize native netty open ssl libs still neccessary
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                System.setProperty("opensearch.set.netty.runtime.available.processors", "false");
                PlatformDependent.newFixedMpscQueue(1);
                OpenSsl.isAvailable();
                return null;
            }
        });

        this.settings = settings;
        this.sharedGroupFactory = new SharedGroupFactory(settings);
        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, settings);
        DefaultObjectMapper.inject(injectableValues);
        NonValidatingObjectMapper.inject(injectableValues);

        client = !"node".equals(this.settings.get(OpenSearchSecuritySSLPlugin.CLIENT_TYPE));

        httpSSLEnabled = settings.getAsBoolean(
            SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED,
            SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_DEFAULT
        );
        transportSSLEnabled = settings.getAsBoolean(
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED,
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT
        );
        extendedKeyUsageEnabled = settings.getAsBoolean(
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED,
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT
        );

        if (!httpSSLEnabled && !transportSSLEnabled) {
            log.error("SSL not activated for http and/or transport.");
        }

        if (ExternalSecurityKeyStore.hasExternalSslContext(settings)) {
            this.sks = new ExternalSecurityKeyStore(settings);
        } else {
            this.sks = new DefaultSecurityKeyStore(settings, configPath);
        }
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getSecureHttpTransports(
        Settings settings,
        ThreadPool threadPool,
        BigArrays bigArrays,
        PageCacheRecycler pageCacheRecycler,
        CircuitBreakerService circuitBreakerService,
        NamedXContentRegistry xContentRegistry,
        NetworkService networkService,
        Dispatcher dispatcher,
        ClusterSettings clusterSettings,
        SecureHttpTransportSettingsProvider secureHttpTransportSettingsProvider,
        Tracer tracer
    ) {

        if (!client && httpSSLEnabled) {

            final ValidatingDispatcher validatingDispatcher = new ValidatingDispatcher(
                threadPool.getThreadContext(),
                dispatcher,
                settings,
                configPath,
                NOOP_SSL_EXCEPTION_HANDLER
            );
            final SecureNetty4HttpServerTransport sgsnht = new SecureNetty4HttpServerTransport(
                migrateSettings(settings),
                networkService,
                bigArrays,
                threadPool,
                xContentRegistry,
                validatingDispatcher,
                clusterSettings,
                sharedGroupFactory,
                secureHttpTransportSettingsProvider,
                tracer
            );

            return Collections.singletonMap("org.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport", () -> sgsnht);

        }
        return Collections.emptyMap();

    }

    @Override
    public List<RestHandler> getRestHandlers(
        Settings settings,
        RestController restController,
        ClusterSettings clusterSettings,
        IndexScopedSettings indexScopedSettings,
        SettingsFilter settingsFilter,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<DiscoveryNodes> nodesInCluster
    ) {

        final List<RestHandler> handlers = new ArrayList<RestHandler>(1);

        if (!client) {
            handlers.add(new SecuritySSLInfoAction(settings, configPath, restController, sks, Objects.requireNonNull(principalExtractor)));
        }

        return handlers;
    }

    @Override
    public List<TransportInterceptor> getTransportInterceptors(NamedWriteableRegistry namedWriteableRegistry, ThreadContext threadContext) {
        List<TransportInterceptor> interceptors = new ArrayList<TransportInterceptor>(1);

        if (transportSSLEnabled && !client) {
            interceptors.add(new SecuritySSLTransportInterceptor(settings, null, null, SSLConfig, NOOP_SSL_EXCEPTION_HANDLER));
        }

        return interceptors;
    }

    @Override
    public Map<String, Supplier<Transport>> getSecureTransports(
        Settings settings,
        ThreadPool threadPool,
        PageCacheRecycler pageCacheRecycler,
        CircuitBreakerService circuitBreakerService,
        NamedWriteableRegistry namedWriteableRegistry,
        NetworkService networkService,
        SecureTransportSettingsProvider secureTransportSettingsProvider,
        Tracer tracer
    ) {

        Map<String, Supplier<Transport>> transports = new HashMap<String, Supplier<Transport>>();
        if (transportSSLEnabled) {
            transports.put(
                "org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport",
                () -> new SecureNetty4Transport(
                    migrateSettings(settings),
                    Version.CURRENT,
                    threadPool,
                    networkService,
                    pageCacheRecycler,
                    namedWriteableRegistry,
                    circuitBreakerService,
                    sharedGroupFactory,
                    secureTransportSettingsProvider,
                    tracer
                )
            );

        }
        return transports;

    }

    @Override
    public Collection<Object> createComponents(
        Client localClient,
        ClusterService clusterService,
        ThreadPool threadPool,
        ResourceWatcherService resourceWatcherService,
        ScriptService scriptService,
        NamedXContentRegistry xContentRegistry,
        Environment environment,
        NodeEnvironment nodeEnvironment,
        NamedWriteableRegistry namedWriteableRegistry,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {

        this.threadPool = threadPool;
        final List<Object> components = new ArrayList<>(1);

        if (client) {
            return components;
        }

        final String principalExtractorClass = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, null);

        if (principalExtractorClass == null) {
            principalExtractor = new DefaultPrincipalExtractor();
        } else {
            try {
                log.debug("Try to load and instantiate '{}'", principalExtractorClass);
                Class<?> principalExtractorClazz = Class.forName(principalExtractorClass);
                principalExtractor = (PrincipalExtractor) principalExtractorClazz.newInstance();
            } catch (Exception e) {
                log.error("Unable to load '{}' due to", principalExtractorClass, e);
                throw new OpenSearchException(e);
            }
        }

        components.add(principalExtractor);

        return components;
    }

    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();

        // add secure settings (with fallbacks for legacy insecure settings)
        settings.addAll(SecureSSLSettings.getSecureSettings());

        // add non secure settings
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(
            Setting.boolSetting(
                SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE,
                OPENSSL_SUPPORTED,
                Property.NodeScope,
                Property.Filtered
            )
        );
        settings.add(
            Setting.boolSetting(
                SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED,
                SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_DEFAULT,
                Property.NodeScope,
                Property.Filtered
            )
        );
        settings.add(
            Setting.boolSetting(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE,
                OPENSSL_SUPPORTED,
                Property.NodeScope,
                Property.Filtered
            )
        );
        settings.add(
            Setting.boolSetting(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED,
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT,
                Property.NodeScope,
                Property.Filtered
            )
        );
        if (!settings.stream().anyMatch(s -> s.getKey().equalsIgnoreCase(NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY))) {
            settings.add(SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION);
        }
        if (!settings.stream()
            .anyMatch(s -> s.getKey().equalsIgnoreCase(NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME_KEY))) {
            settings.add(SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME);
        }
        settings.add(
            Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered)
        );
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(
            Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered)
        );
        settings.add(
            Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered)
        );
        settings.add(
            Setting.listSetting(
                SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS,
                Collections.emptyList(),
                Function.identity(),
                Property.NodeScope
            )
        );// not filtered here
        settings.add(
            Setting.listSetting(
                SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS,
                Collections.emptyList(),
                Function.identity(),
                Property.NodeScope
            )
        );// not filtered here
        settings.add(
            Setting.listSetting(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS,
                Collections.emptyList(),
                Function.identity(),
                Property.NodeScope
            )
        );// not filtered here
        settings.add(
            Setting.listSetting(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS,
                Collections.emptyList(),
                Function.identity(),
                Property.NodeScope
            )
        );// not filtered here
        settings.add(
            Setting.simpleString(SSLConfigConstants.SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID, Property.NodeScope, Property.Filtered)
        );
        settings.add(
            Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, Property.NodeScope, Property.Filtered)
        );

        settings.add(
            Setting.boolSetting(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED,
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT,
                Property.NodeScope,
                Property.Filtered
            )
        );
        if (extendedKeyUsageEnabled) {
            settings.add(
                Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered)
            );
            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS,
                    Property.NodeScope,
                    Property.Filtered
                )
            );

            settings.add(
                Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered)
            );
            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS,
                    Property.NodeScope,
                    Property.Filtered
                )
            );

            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH,
                    Property.NodeScope,
                    Property.Filtered
                )
            );
            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH,
                    Property.NodeScope,
                    Property.Filtered
                )
            );
            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH,
                    Property.NodeScope,
                    Property.Filtered
                )
            );

            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH,
                    Property.NodeScope,
                    Property.Filtered
                )
            );
            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH,
                    Property.NodeScope,
                    Property.Filtered
                )
            );
            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH,
                    Property.NodeScope,
                    Property.Filtered
                )
            );
        } else {
            settings.add(
                Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered)
            );
            settings.add(
                Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered)
            );

            settings.add(
                Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered)
            );
            settings.add(
                Setting.simpleString(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered)
            );
            settings.add(
                Setting.simpleString(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                    Property.NodeScope,
                    Property.Filtered
                )
            );
        }
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(
            Setting.simpleString(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered)
        );

        settings.add(Setting.simpleString(SSLConfigConstants.SSECURITY_SSL_HTTP_CRL_FILE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, false, Property.NodeScope, Property.Filtered));
        settings.add(
            Setting.boolSetting(
                SSLConfigConstants.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP,
                false,
                Property.NodeScope,
                Property.Filtered
            )
        );
        settings.add(
            Setting.boolSetting(
                SSLConfigConstants.SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES,
                true,
                Property.NodeScope,
                Property.Filtered
            )
        );
        settings.add(
            Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, false, Property.NodeScope, Property.Filtered)
        );
        settings.add(
            Setting.boolSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, false, Property.NodeScope, Property.Filtered)
        );
        settings.add(
            Setting.longSetting(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, -1, -1, Property.NodeScope, Property.Filtered)
        );

        return settings;
    }

    @Override
    public Settings additionalSettings() {
        final Settings.Builder builder = Settings.builder();

        if (!client && httpSSLEnabled) {

            if (settings.get("http.compression") == null) {
                builder.put("http.compression", false);
                log.info(
                    "Disabled https compression by default to mitigate BREACH attacks. You can enable it by setting 'http.compression: true' in opensearch.yml"
                );
            }

            builder.put(NetworkModule.HTTP_TYPE_KEY, "org.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport");
        }

        if (transportSSLEnabled) {
            builder.put(NetworkModule.TRANSPORT_TYPE_KEY, "org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport");
        }

        return builder.build();
    }

    @Override
    public List<String> getSettingsFilter() {
        List<String> settingsFilter = new ArrayList<>();
        settingsFilter.add("opendistro_security.*");
        settingsFilter.add("plugins.security.*");
        return settingsFilter;
    }

    @Override
    public Optional<SecureSettingsFactory> getSecureSettingFactory(Settings settings) {
        return Optional.of(new OpenSearchSecureSettingsFactory(threadPool, sks, NOOP_SSL_EXCEPTION_HANDLER, securityRestHandler));
    }

    protected Settings migrateSettings(Settings settings) {
        final Settings.Builder builder = Settings.builder().put(settings);

        if (!NetworkModule.TRANSPORT_SSL_DUAL_MODE_ENABLED.exists(settings)) {
            builder.put(NetworkModule.TRANSPORT_SSL_DUAL_MODE_ENABLED_KEY, SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings));
        } else {
            if (SecuritySettings.SSL_DUAL_MODE_SETTING.exists(settings)) {
                throw new OpenSearchException(
                    "Only one of the settings ["
                        + NetworkModule.TRANSPORT_SSL_DUAL_MODE_ENABLED_KEY
                        + ", "
                        + SecuritySettings.SSL_DUAL_MODE_SETTING.getKey()
                        + " (deprecated)] could be specified but not both"
                );
            }
        }

        if (!NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME.exists(settings)) {
            builder.put(
                NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME_KEY,
                SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME.get(settings)
            );
        } else {
            if (SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME.exists(settings)) {
                throw new OpenSearchException(
                    "Only one of the settings ["
                        + NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME_KEY
                        + ", "
                        + SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME.getKey()
                        + " (deprecated)] could be specified but not both"
                );
            }
        }

        if (!NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION.exists(settings)) {
            builder.put(
                NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY,
                SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION.get(settings)
            );
        } else {
            if (SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION.exists(settings)) {
                throw new OpenSearchException(
                    "Only one of the settings ["
                        + NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY
                        + ", "
                        + SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION.getKey()
                        + " (deprecated)] could be specified but not both"
                );
            }
        }

        return builder.build();
    }
}
