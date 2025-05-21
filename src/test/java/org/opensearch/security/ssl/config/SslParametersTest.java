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
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslProvider;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.CLIENT_AUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_AUX_PREFIX;
import static org.junit.Assert.assertThrows;

public class SslParametersTest {

    private List<String> finalDefaultCiphers;

    private static final String MOCK_AUX_PREFIX_FOO = SSL_AUX_PREFIX + "foo.";
    private static final String MOCK_AUX_PREFIX_BAR = SSL_AUX_PREFIX + "bar.";
    private static final CertType MOCK_AUX_CERT_TYPE_FOO = new CertType(MOCK_AUX_PREFIX_FOO);
    private static final CertType MOCK_AUX_CERT_TYPE_BAR = new CertType(MOCK_AUX_PREFIX_BAR);

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
        final var httpSslParameters = SslParameters.loader(CertType.HTTP, Settings.EMPTY).load();
        assertThat(httpSslParameters.provider(), is(SslProvider.JDK));
        assertThat(httpSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(httpSslParameters.allowedCiphers(), is(finalDefaultCiphers));
        assertThat(httpSslParameters.clientAuth(), is(ClientAuth.OPTIONAL));
    }

    @Test
    public void testDefaultSslParametersForAux() {
        final var auxSslParameters = SslParameters.loader(MOCK_AUX_CERT_TYPE_FOO, Settings.EMPTY).load();
        assertThat(auxSslParameters.provider(), is(SslProvider.JDK));
        assertThat(auxSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(auxSslParameters.allowedCiphers(), is(finalDefaultCiphers));
        assertThat(auxSslParameters.clientAuth(), is(ClientAuth.OPTIONAL));
    }

    @Test
    public void testDefaultSslParametersForTransport() {
        final var transportSslParameters = SslParameters.loader(CertType.TRANSPORT, Settings.EMPTY).load();
        assertThat(transportSslParameters.provider(), is(SslProvider.JDK));
        assertThat(transportSslParameters.allowedProtocols(), is(List.of("TLSv1.3", "TLSv1.2")));
        assertThat(transportSslParameters.allowedCiphers(), is(finalDefaultCiphers));
        assertThat(transportSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
    }

    @Test
    public void testCustomSSlParametersForHttp() {
        final Settings settings = Settings.builder()
            .put(SECURITY_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .putList(SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, List.of("TLSv1.2", "TLSv1"))
            .putList(SECURITY_SSL_HTTP_ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
            .build();
        final SslParameters httpSslParameters = SslParameters.loader(CertType.HTTP, settings).load();
        assertThat(httpSslParameters.provider(), is(SslProvider.JDK));
        assertThat(httpSslParameters.allowedProtocols(), is(List.of("TLSv1.2")));
        assertThat(httpSslParameters.allowedCiphers(), is(List.of("TLS_AES_256_GCM_SHA384")));
        assertThat(httpSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
    }

    @Test
    public void testCustomSSlParametersForAux() {
        final Settings settings = Settings.builder()
            .put(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + CLIENT_AUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .putList(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + ENABLED_PROTOCOLS, List.of("TLSv1.2", "TLSv1"))
            .putList(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
            .build();
        final SslParameters auxSslParameters = SslParameters.loader(MOCK_AUX_CERT_TYPE_FOO, settings).load();
        assertThat(auxSslParameters.provider(), is(SslProvider.JDK));
        assertThat(auxSslParameters.allowedProtocols(), is(List.of("TLSv1.2")));
        assertThat(auxSslParameters.allowedCiphers(), is(List.of("TLS_AES_256_GCM_SHA384")));
        assertThat(auxSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
    }

    @Test
    public void testCustomSSlParametersForMultiAux() {
        final Settings settings = Settings.builder()
            .put(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + CLIENT_AUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .putList(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + ENABLED_PROTOCOLS, List.of("TLSv1.2", "TLSv1"))
            .putList(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
            .put(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + CLIENT_AUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .putList(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + ENABLED_PROTOCOLS, List.of("TLSv1.3"))
            .putList(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + ENABLED_CIPHERS, List.of("TLS_AES_128_GCM_SHA256", "DNE"))
            .build();
        final SslParameters fooSslParameters = SslParameters.loader(MOCK_AUX_CERT_TYPE_FOO, settings).load();
        assertThat(fooSslParameters.provider(), is(SslProvider.JDK));
        assertThat(fooSslParameters.allowedProtocols(), is(List.of("TLSv1.2")));
        assertThat(fooSslParameters.allowedCiphers(), is(List.of("TLS_AES_256_GCM_SHA384")));
        assertThat(fooSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
        final SslParameters barSslParameters = SslParameters.loader(MOCK_AUX_CERT_TYPE_BAR, settings).load();
        assertThat(barSslParameters.provider(), is(SslProvider.JDK));
        assertThat(barSslParameters.allowedProtocols(), is(List.of("TLSv1.3")));
        assertThat(barSslParameters.allowedCiphers(), is(List.of("TLS_AES_128_GCM_SHA256")));
        assertThat(barSslParameters.clientAuth(), is(ClientAuth.REQUIRE));
    }

    @Test
    public void testSSlParametersEmptyProtocolsFails() {
        final Settings settings = Settings.builder()
            .put(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + CLIENT_AUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .putList(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + ENABLED_PROTOCOLS, List.of("TLSv1"))
            .putList(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
            .build();
        // Intersection of enabled protocols and allowed protocols is empty list.
        assertThrows(OpenSearchSecurityException.class, () -> SslParameters.loader(MOCK_AUX_CERT_TYPE_BAR, settings).load());
    }

    @Test
    public void testCustomSSlParametersForTransport() {
        final Settings settings = Settings.builder()
            .putList(SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, List.of("TLSv1.3", "TLSv1.2"))
            .putList(SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"))
            .build();
        final SslParameters transportSslParameters = SslParameters.loader(CertType.TRANSPORT, settings).load();
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
            .put(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + CLIENT_AUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .putList(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + ENABLED_PROTOCOLS, List.of("TLSv1.2", "TLSv1"))
            .putList(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + ENABLED_CIPHERS, List.of("TLS_AES_256_GCM_SHA384"))
            .putList(SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, List.of("TLSv1.3", "TLSv1.2"))
            .putList(SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"))
            .build();
        final SslParameters httpSslParameters = SslParameters.loader(CertType.HTTP, settings).load();
        final SslParameters auxSslParameters = SslParameters.loader(MOCK_AUX_CERT_TYPE_BAR, settings).load();
        final SslParameters transportSslParameters = SslParameters.loader(CertType.TRANSPORT, settings).load();
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
