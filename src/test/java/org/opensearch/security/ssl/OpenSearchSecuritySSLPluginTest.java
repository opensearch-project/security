/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.network.NetworkModule;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.http.HttpServerTransport;
import org.opensearch.http.netty4.ssl.SecureNetty4HttpServerTransport;
import org.opensearch.plugins.SecureHttpTransportSettingsProvider;
import org.opensearch.plugins.SecureTransportSettingsProvider;
import org.opensearch.plugins.TransportExceptionHandler;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.telemetry.tracing.noop.NoopTracer;
import org.opensearch.transport.Transport;
import org.opensearch.transport.TransportAdapterProvider;

import io.netty.channel.ChannelInboundHandlerAdapter;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsMapContaining.hasKey;
import static org.opensearch.common.network.NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY;
import static org.junit.Assert.assertThrows;

public class OpenSearchSecuritySSLPluginTest extends AbstractSecurityUnitTest {
    private Settings settings;
    private SecureHttpTransportSettingsProvider secureHttpTransportSettingsProvider;
    private SecureTransportSettingsProvider secureTransportSettingsProvider;
    private ClusterSettings clusterSettings;

    private Path osPathHome;

    @Before
    public void setUp() {
        osPathHome = FileHelper.resolveStore("ssl/kirk-keystore").path().getParent().getParent();
        settings = Settings.builder()
            .put(Environment.PATH_HOME_SETTING.getKey(), osPathHome)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.resolveStore("ssl/kirk-keystore").path())
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, FileHelper.resolveStore("ssl/truststore").path())
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.resolveStore("ssl/kirk-keystore").path())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, FileHelper.resolveStore("ssl/node-0-keystore").path())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(OpenSearchSecuritySSLPlugin.CLIENT_TYPE, "node")
            .build();

        secureTransportSettingsProvider = new SecureTransportSettingsProvider() {
            @Override
            public Optional<TransportExceptionHandler> buildServerTransportExceptionHandler(Settings settings, Transport transport) {
                return Optional.empty();
            }

            @Override
            public Optional<SSLEngine> buildSecureServerTransportEngine(Settings settings, Transport transport) throws SSLException {
                return Optional.empty();
            }

            @Override
            public Optional<SSLEngine> buildSecureClientTransportEngine(Settings settings, String hostname, int port) throws SSLException {
                return Optional.empty();
            }
        };

        secureHttpTransportSettingsProvider = new SecureHttpTransportSettingsProvider() {
            @Override
            public Optional<TransportExceptionHandler> buildHttpServerExceptionHandler(Settings settings, HttpServerTransport transport) {
                return Optional.empty();
            }

            @Override
            public Optional<SSLEngine> buildSecureHttpServerEngine(Settings settings, HttpServerTransport transport) throws SSLException {
                return Optional.empty();
            }
        };

        clusterSettings = new ClusterSettings(Settings.EMPTY, ClusterSettings.BUILT_IN_CLUSTER_SETTINGS);
    }

    @Test
    public void testRegisterSecureHttpTransport() throws IOException {
        try (OpenSearchSecuritySSLPlugin plugin = new OpenSearchSecuritySSLPlugin(settings, osPathHome, false)) {
            final Map<String, Supplier<HttpServerTransport>> transports = plugin.getSecureHttpTransports(
                settings,
                MOCK_POOL,
                null,
                null,
                null,
                null,
                null,
                null,
                clusterSettings,
                secureHttpTransportSettingsProvider,
                NoopTracer.INSTANCE
            );
            assertThat(transports, hasKey("org.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport"));
            assertThat(
                transports.get("org.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport").get(),
                not(nullValue())
            );
        }
    }

    @Test
    public void testRegisterSecureTransport() throws IOException {
        try (OpenSearchSecuritySSLPlugin plugin = new OpenSearchSecuritySSLPlugin(settings, osPathHome, false)) {
            final Map<String, Supplier<Transport>> transports = plugin.getSecureTransports(
                settings,
                MOCK_POOL,
                null,
                null,
                null,
                null,
                secureTransportSettingsProvider,
                NoopTracer.INSTANCE
            );
            assertThat(transports, hasKey("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport"));
            assertThat(transports.get("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport").get(), not(nullValue()));
        }
    }

    @Test
    public void testRegisterSecureTransportWithDeprecatedSecuirtyPluginSettings() throws IOException {
        final Settings deprecated = Settings.builder()
            .put(settings)
            .put(SecuritySettings.SSL_DUAL_MODE_SETTING.getKey(), true)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .put(TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY, false)
            .build();

        try (OpenSearchSecuritySSLPlugin plugin = new OpenSearchSecuritySSLPlugin(deprecated, osPathHome, false)) {
            final Map<String, Supplier<Transport>> transports = plugin.getSecureTransports(
                deprecated,
                MOCK_POOL,
                null,
                null,
                null,
                null,
                secureTransportSettingsProvider,
                NoopTracer.INSTANCE
            );
            assertThat(transports, hasKey("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport"));
            assertThat(transports.get("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport").get(), not(nullValue()));
        }
    }

    @Test
    public void testRegisterSecureTransportWithNetworkModuleSettings() throws IOException {
        final Settings migrated = Settings.builder()
            .put(settings)
            .put(NetworkModule.TRANSPORT_SSL_DUAL_MODE_ENABLED_KEY, true)
            .put(NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME_KEY, false)
            .put(TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY, false)
            .build();

        try (OpenSearchSecuritySSLPlugin plugin = new OpenSearchSecuritySSLPlugin(migrated, osPathHome, false)) {
            final Map<String, Supplier<Transport>> transports = plugin.getSecureTransports(
                migrated,
                MOCK_POOL,
                null,
                null,
                null,
                null,
                secureTransportSettingsProvider,
                NoopTracer.INSTANCE
            );
            assertThat(transports, hasKey("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport"));
            assertThat(transports.get("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport").get(), not(nullValue()));
        }
    }

    @Test
    public void testSecureTransportParametersFollowTheTransport() throws IOException {
        // Only the security plugin's own (deprecated) keys: the node settings do not hold the core keys,
        // so the provider must report the values its transport uses after migrateSettings.
        final Settings own = Settings.builder()
            .put(settings)
            .put("plugins.security.ssl.transport.enforce_hostname_verification", false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .build();

        try (OpenSearchSecuritySSLPlugin plugin = new OpenSearchSecuritySSLPlugin(own, osPathHome, false)) {
            final SecureTransportSettingsProvider provider = plugin.getSecureSettingFactory(own)
                .orElseThrow()
                .getSecureTransportSettingsProvider(own)
                .orElseThrow();
            final SecureTransportSettingsProvider.SecureTransportParameters parameters = provider.parameters(own).orElseThrow();
            assertThat(parameters.enforceHostnameVerification(), is(Optional.of(false)));
            assertThat(parameters.resolveHostname(), is(Optional.of(false)));
            assertThat(parameters.keyManagerFactory().isPresent(), is(true));
            assertThat(parameters.clientKeyManagerFactory().isPresent(), is(true));
            assertThat(parameters.trustManagerFactory().isPresent(), is(true));
            // The client side has its own context, so the client trust material is not the server instance.
            assertThat(
                parameters.clientTrustManagerFactory().orElseThrow(),
                not(sameInstance(parameters.trustManagerFactory().orElseThrow()))
            );
            // The SSL plugin alone has no node rules.
            assertThat(provider.isNodeCertificate(new X509Certificate[0]), is(Optional.empty()));
        }
    }

    @Test
    public void testRegisterSecureTransportWithDuplicateSettings() throws IOException {
        final Collection<Tuple<String, String>> duplicates = List.of(
            Tuple.tuple(SecuritySettings.SSL_DUAL_MODE_SETTING.getKey(), NetworkModule.TRANSPORT_SSL_DUAL_MODE_ENABLED_KEY),
            Tuple.tuple(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME,
                NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME_KEY
            ),
            Tuple.tuple(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_KEY,
                TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY
            )
        );

        for (final Tuple<String, String> duplicate : duplicates) {
            final Settings migrated = Settings.builder()
                .put(settings)
                .put(duplicate.v1(), true)
                .put(NetworkModule.TRANSPORT_SSL_DUAL_MODE_ENABLED_KEY, true)
                .put(NetworkModule.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME_KEY, false)
                .put(TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY, false)
                .build();

            try (OpenSearchSecuritySSLPlugin plugin = new OpenSearchSecuritySSLPlugin(migrated, osPathHome, false)) {
                final Map<String, Supplier<Transport>> transports = plugin.getSecureTransports(
                    migrated,
                    MOCK_POOL,
                    null,
                    null,
                    null,
                    null,
                    secureTransportSettingsProvider,
                    NoopTracer.INSTANCE
                );
                assertThat(transports, hasKey("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport"));
                final OpenSearchException ex = assertThrows(
                    OpenSearchException.class,
                    transports.get("org.opensearch.security.ssl.http.netty.SecuritySSLNettyTransport")::get
                );
                assertThat(
                    ex.getMessage(),
                    containsString(
                        "Only one of the settings ["
                            + duplicate.v2()
                            + ", "
                            + duplicate.v1()
                            + " (deprecated)] could be specified but not both"
                    )
                );
            }
        }
    }

    @Test
    public void testRegisterSecureHttpTransportWithRequestHeaderVerifier() throws IOException {
        final AtomicBoolean created = new AtomicBoolean(false);

        class LocalHeaderVerifier extends ChannelInboundHandlerAdapter {
            public LocalHeaderVerifier() {
                created.set(true);
            }
        }

        final SecureHttpTransportSettingsProvider provider = new SecureHttpTransportSettingsProvider() {
            @Override
            public Collection<TransportAdapterProvider<HttpServerTransport>> getHttpTransportAdapterProviders(Settings settings) {
                return List.of(new TransportAdapterProvider<HttpServerTransport>() {

                    @Override
                    public String name() {
                        return SecureNetty4HttpServerTransport.REQUEST_HEADER_VERIFIER;
                    }

                    @SuppressWarnings("unchecked")
                    @Override
                    public <C> Optional<C> create(Settings settings, HttpServerTransport transport, Class<C> adapterClass) {
                        return Optional.of((C) new LocalHeaderVerifier());
                    }

                });
            }

            @Override
            public Optional<TransportExceptionHandler> buildHttpServerExceptionHandler(Settings settings, HttpServerTransport transport) {
                return Optional.empty();
            }

            @Override
            public Optional<SSLEngine> buildSecureHttpServerEngine(Settings settings, HttpServerTransport transport) throws SSLException {
                return Optional.empty();
            }
        };

        try (OpenSearchSecuritySSLPlugin plugin = new OpenSearchSecuritySSLPlugin(settings, null, false)) {
            final Map<String, Supplier<HttpServerTransport>> transports = plugin.getSecureHttpTransports(
                settings,
                MOCK_POOL,
                null,
                null,
                null,
                null,
                null,
                null,
                clusterSettings,
                provider,
                NoopTracer.INSTANCE
            );
            assertThat(transports, hasKey("org.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport"));

            assertThat(
                transports.get("org.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport").get(),
                not(nullValue())
            );

            assertThat(created.get(), is(true));
        }
    }
}
