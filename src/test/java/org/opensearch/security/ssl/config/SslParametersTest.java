/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.ssl.config;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.SSLContext;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslProvider;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_AUX_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;

public class SslParametersTest {

    List<String> finalDefaultCiphers;

    @Before
    public void setup() throws NoSuchAlgorithmException {
        final var defaultCiphers = List.of(ALLOWED_SSL_CIPHERS);
        finalDefaultCiphers = Stream.of(SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites())
            .filter(defaultCiphers::contains)
            .sorted(String::compareTo)
            .collect(Collectors.toList());
    }

    @Test
    public void testDefaultSslParametersForHttp() {
        final var httpSslParameters = SslParameters.loader(Settings.EMPTY).load(CertType.HTTP);
        assertThat(httpSslParameters.provider(), is(SslProvider.JDK));
        assertThat(httpSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(httpSslParameters.allowedCiphers(), is(finalDefaultCiphers));
        assertThat(httpSslParameters.clientAuth(), is(ClientAuth.OPTIONAL));
    }

    @Test
    public void testDefaultSslParametersForAux() {
        final var auxSslParameters = SslParameters.loader(Settings.EMPTY).load(CertType.AUX);
        assertThat(auxSslParameters.provider(), is(SslProvider.JDK));
        assertThat(auxSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(auxSslParameters.allowedCiphers(), is(finalDefaultCiphers));
        assertThat(auxSslParameters.clientAuth(), is(ClientAuth.OPTIONAL));
    }

    @Test
    public void testDefaultSslParametersForTransport() {
        final var transportSslParameters = SslParameters.loader(Settings.EMPTY).load(CertType.TRANSPORT);
        assertThat(transportSslParameters.provider(), is(SslProvider.JDK));
        assertThat(transportSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(transportSslParameters.allowedCiphers(), is(finalDefaultCiphers));
        assertThat(transportSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
    }

    @Test
    public void testCustomSSlParametersForHttpAndTransport() {
        final var settings = Settings.builder()
                .put(SECURITY_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
                .putList(SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, List.of("TLSv1.2", "TLSv1"))
                .putList(SECURITY_SSL_HTTP_ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
                .putList(SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, List.of("TLSv1.3", "TLSv1.2"))
                .putList(SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"))
                .build();
        final var httpSslParameters = SslParameters.loader(settings.getByPrefix(SSL_HTTP_PREFIX)).load(CertType.HTTP);
        final var transportSslParameters = SslParameters.loader(settings.getByPrefix(SSL_TRANSPORT_PREFIX)).load(CertType.TRANSPORT);

        assertThat(httpSslParameters.provider(), is(SslProvider.JDK));
        assertThat(httpSslParameters.allowedProtocols(), is(List.of("TLSv1.2")));
        assertThat(httpSslParameters.allowedCiphers(), is(List.of("TLS_AES_256_GCM_SHA384")));
        assertThat(httpSslParameters.clientAuth(), is(ClientAuth.REQUIRE));

        assertThat(transportSslParameters.provider(), is(SslProvider.JDK));
        assertThat(transportSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(transportSslParameters.allowedCiphers(), is(List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384")));
        assertThat(transportSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
    }

    @Test
    public void testCustomSSlParametersForHttpAndAuxAndTransport() {
        final var settings = Settings.builder()
                .put(SECURITY_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
                .putList(SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, List.of("TLSv1.2", "TLSv1"))
                .putList(SECURITY_SSL_HTTP_ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
                .put(SECURITY_SSL_AUX_CLIENTAUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
                .putList(SECURITY_SSL_AUX_ENABLED_PROTOCOLS, List.of("TLSv1.2", "TLSv1"))
                .putList(SECURITY_SSL_AUX_ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
                .putList(SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, List.of("TLSv1.3", "TLSv1.2"))
                .putList(SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"))
                .build();

        final var httpSslParameters = SslParameters.loader(settings.getByPrefix(SSL_HTTP_PREFIX)).load(CertType.HTTP);
        final var auxSslParameters = SslParameters.loader(settings.getByPrefix(SSL_AUX_PREFIX)).load(CertType.AUX);
        final var transportSslParameters = SslParameters.loader(settings.getByPrefix(SSL_TRANSPORT_PREFIX)).load(CertType.TRANSPORT);

        assertThat(httpSslParameters.provider(), is(SslProvider.JDK));
        assertThat(httpSslParameters.allowedProtocols(), is(List.of("TLSv1.2")));
        assertThat(httpSslParameters.allowedCiphers(), is(List.of("TLS_AES_256_GCM_SHA384")));
        assertThat(httpSslParameters.clientAuth(), is(ClientAuth.REQUIRE));

        assertThat(auxSslParameters.provider(), is(SslProvider.JDK));
        assertThat(auxSslParameters.allowedProtocols(), is(List.of("TLSv1.2")));
        assertThat(auxSslParameters.allowedCiphers(), is(List.of("TLS_AES_256_GCM_SHA384")));
        assertThat(auxSslParameters.clientAuth(), is(ClientAuth.REQUIRE));

        assertThat(transportSslParameters.provider(), is(SslProvider.JDK));
        assertThat(transportSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(transportSslParameters.allowedCiphers(), is(List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384")));
        assertThat(transportSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
    }
}
