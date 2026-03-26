/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.util;

import org.junit.Test;
import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.env.Environment;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.util.FakeRestRequest;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SSLRequestHelperTest {

    /** Matches the fixed validation date used in CertificateValidatorTest. */
    private static final Date FIXED_CRL_DATE = new Date(1525546426000L);

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Returns the absolute path to src/test/resources/ssl, used as configDir. */
    private static Path sslDir() {
        return FileHelper.getAbsoluteFilePathFromClassPath("ssl");
    }

    /**
     * Builds an Environment whose configDir() returns the given path.
     * A dummy path.home is required by the Environment constructor even when
     * configPath overrides the config directory.
     */
    private static Environment env(Path configDir) {
        Settings base = Settings.builder().put("path.home", configDir.getParent().toString()).build();
        return new Environment(base, configDir);
    }

    private static X509Certificate[] loadCerts(String classpathResource) throws Exception {
        try (FileInputStream fis = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath(classpathResource).toFile())) {
            Collection<? extends java.security.cert.Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(fis);
            return certs.stream().map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
        }
    }

    private static Collection<? extends CRL> loadCrls(String classpathResource) throws Exception {
        try (FileInputStream fis = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath(classpathResource).toFile())) {
            return CertificateFactory.getInstance("X.509").generateCRLs(fis);
        }
    }

    // ── trustAnchorsFrom ─────────────────────────────────

    @Test
    public void trustAnchorsFromCerts_returnsOneAnchorPerCert_forMultipleCerts() throws Exception {
        X509Certificate[] certs = loadCerts("ssl/chain-ca.pem"); // root + intermediate = 2 certs

        Set<TrustAnchor> anchors = SSLRequestHelper.trustAnchorsFrom(certs);

        assertThat(anchors.size(), is(certs.length));
        Set<X509Certificate> anchorCerts = anchors.stream().map(TrustAnchor::getTrustedCert).collect(Collectors.toSet());
        for (X509Certificate cert : certs) {
            assertThat(anchorCerts.contains(cert), is(true));
        }
    }

    @Test
    public void trustAnchorsFromKeyStore_returnsAnchorForEachCertificateEntry() throws Exception {
        KeyStore ts = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore_valid.jks").toFile()
        )) {
            ts.load(fis, null);
        }

        Set<TrustAnchor> anchors = SSLRequestHelper.trustAnchorsFrom(ts);

        assertThat(anchors.size(), is(ts.size()));
        for (TrustAnchor anchor : anchors) {
            assertThat(anchor.getTrustedCert(), is(notNullValue()));
            assertThat(anchor.getNameConstraints(), is(nullValue()));
        }
    }

    // ── configureValidator ───────────────────────────────────────────────────

    @Test
    public void configureValidator_appliesDefaults() throws Exception {
        CertificateValidator validator = new CertificateValidator(SSLRequestHelper.trustAnchorsFrom(loadCerts("ssl/root-ca.pem")), null);

        SSLRequestHelper.configureValidator(validator, Settings.EMPTY);

        // !disable_crldp(false) → true;  !disable_ocsp(false) → true
        assertThat(validator.isEnableCRLDP(), is(true));
        assertThat(validator.isEnableOCSP(), is(true));
        assertThat(validator.isCheckOnlyEndEntities(), is(true));
        assertThat(validator.isPreferCrl(), is(false));
        assertThat(validator.getDate(), is(nullValue()));
    }

    @Test
    public void configureValidator_disablesCrldpAndOcsp_whenExplicitlyDisabled() throws Exception {
        CertificateValidator validator = new CertificateValidator(SSLRequestHelper.trustAnchorsFrom(loadCerts("ssl/root-ca.pem")), null);
        Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, FIXED_CRL_DATE.getTime())
            .build();

        SSLRequestHelper.configureValidator(validator, settings);

        assertThat(validator.isEnableCRLDP(), is(false));
        assertThat(validator.isEnableOCSP(), is(false));
        assertThat(validator.isPreferCrl(), is(true));
        assertThat(validator.getDate(), is(FIXED_CRL_DATE));
    }

    @Test
    public void configureValidator_leavesDateNull_whenTimestampIsNegative() throws Exception {
        CertificateValidator validator = new CertificateValidator(SSLRequestHelper.trustAnchorsFrom(loadCerts("ssl/root-ca.pem")), null);
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, -1L).build();

        SSLRequestHelper.configureValidator(validator, settings);

        assertThat(validator.getDate(), is(nullValue()));
    }

    // ── SSLInfo.toString ──────────────────────────────────────────────────────

    @Test
    public void sslInfoToString_containsAllFields() {
        SSLRequestHelper.SSLInfo info = new SSLRequestHelper.SSLInfo(null, "CN=test", "TLSv1.3", "TLS_AES_256_GCM_SHA384", null);

        assertThat(info.toString(), is("SSLInfo [x509Certs=null, principal=CN=test, protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384]"));
    }

    // ── loadCrls ─────────────────────────────────────────────────────────────

    @Test
    public void loadCrls_returnsNull_whenNoCrlFileConfigured() throws Exception {
        Collection<? extends CRL> crls = SSLRequestHelper.loadCrls(Settings.EMPTY, env(sslDir()));

        assertThat(crls, is(nullValue()));
    }

    @Test
    public void loadCrls_loadsCrlsFromFile_whenConfigured() throws Exception {
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, "crl/revoked.crl").build();

        Collection<? extends CRL> crls = SSLRequestHelper.loadCrls(settings, env(sslDir()));

        assertThat(crls, is(notNullValue()));
        assertThat(crls.size(), is(1));
        assertThat(
            crls.iterator().next().toString(),
            containsString("CN=Example Com Inc. Signing CA, OU=Example Com Inc. Signing CA, O=Example Com Inc., DC=example, DC=com")
        );
    }

    // ── buildValidatorFromPem ─────────────────────────────────────────────────

    @Test
    public void buildValidatorFromPem_buildsValidator_usingPemTrustedCAs() throws Exception {
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "chain-ca.pem").build();

        CertificateValidator validator = SSLRequestHelper.buildValidatorFromPem(settings, env(sslDir()), null);

        assertThat(validator, is(notNullValue()));
    }

    @Test
    public void buildValidatorFromPem_propagatesCrls_toValidator() throws Exception {
        Collection<? extends CRL> crls = loadCrls("ssl/crl/revoked.crl");
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "chain-ca.pem").build();

        CertificateValidator validator = SSLRequestHelper.buildValidatorFromPem(settings, env(sslDir()), crls);

        assertThat(validator.getCrls(), is(crls));
    }

    // ── buildValidatorFromTruststore ──────────────────────────────────────────

    @Test
    public void buildValidatorFromTruststore_buildsValidator_usingJksKeystore() throws Exception {
        // truststore_valid.jks has no password — null is passed to KeyStore.load()
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, "JKS").build();

        CertificateValidator validator =
            SSLRequestHelper.buildValidatorFromTruststore(settings, env(sslDir()), null, "truststore_valid.jks");

        assertThat(validator, is(notNullValue()));
    }

    // ── buildValidator (dispatcher) ───────────────────────────────────────────

    @Test
    public void buildValidator_dispatchesToTruststore_whenTruststoreFilepathSet() throws Exception {
        Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, "truststore_valid.jks")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, "JKS")
            .build();

        CertificateValidator validator = SSLRequestHelper.buildValidator(settings, env(sslDir()), null);

        assertThat(validator, is(notNullValue()));
    }

    @Test
    public void buildValidator_dispatchesToPem_whenNoTruststoreFilepathSet() throws Exception {
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "chain-ca.pem").build();

        CertificateValidator validator = SSLRequestHelper.buildValidator(settings, env(sslDir()), null);

        assertThat(validator, is(notNullValue()));
    }

    // ── validate (orchestrator) ───────────────────────────────────────────────

    @Test
    public void validate_doesNotThrow_whenCrlValidationIsDisabled() throws Exception {
        // Even a revoked cert must not cause an exception when validate=false
        X509Certificate[] revokedChain = loadCerts("ssl/crl/revoked.crt.pem");
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, false).build();

        SSLRequestHelper.validate(revokedChain, settings, sslDir());
        // no exception expected
    }

    @Test
    public void validate_throwsCertificateException_forRevokedCert() throws Exception {
        X509Certificate[] revokedChain = loadCerts("ssl/crl/revoked.crt.pem");
        Settings settings = Settings.builder()
            .put("path.home", sslDir().getParent().toString())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, "crl/revoked.crl")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "chain-ca.pem")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, FIXED_CRL_DATE.getTime())
            .build();

        try {
            SSLRequestHelper.validate(revokedChain, settings, sslDir());
            fail("Expected CertPathValidatorException for revoked certificate");
        } catch (CertPathValidatorException e) {
            // expected — revocation detected directly without wrapping
        }
    }

    // ── containsBadHeader ─────────────────────────────────────────────────────

    @Test
    public void containsBadHeader_returnsFalse_whenContextIsNull() {
        assertThat(SSLRequestHelper.containsBadHeader(null, "_opendistro"), is(false));
    }

    @Test
    public void containsBadHeader_returnsFalse_whenNoHeaders() {
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        assertThat(SSLRequestHelper.containsBadHeader(context, "_opendistro"), is(false));
    }

    @Test
    public void containsBadHeader_returnsTrue_whenHeaderMatchesPrefix() {
        ThreadContext context = new ThreadContext(Settings.EMPTY);
        context.putHeader("_opendistro_security_user", "attacker");

        assertThat(SSLRequestHelper.containsBadHeader(context, "_opendistro"), is(true));
    }

    @Test
    public void containsBadHeader_isCaseInsensitiveOnHeaderName() {
        ThreadContext context = new ThreadContext(Settings.EMPTY);
        context.putHeader("_OPENDISTRO_Security_User", "attacker");

        assertThat(SSLRequestHelper.containsBadHeader(context, "_opendistro"), is(true));
    }

    @Test
    public void containsBadHeader_returnsFalse_whenNoPrefixMatch() {
        ThreadContext context = new ThreadContext(Settings.EMPTY);
        context.putHeader("Authorization", "Bearer token");
        context.putHeader("Content-Type", "application/json");

        assertThat(SSLRequestHelper.containsBadHeader(context, "_opendistro"), is(false));
    }

    // ── getSSLInfo ────────────────────────────────────────────────────────────

    @Test
    public void getSSLInfo_returnsNull_whenNoSslEngine() throws Exception {
        SecurityRequest request = new FakeRestRequest(Collections.emptyMap(), Collections.emptyMap()).asSecurityRequest();

        assertThat(SSLRequestHelper.getSSLInfo(Settings.EMPTY, sslDir(), request, null), is(nullValue()));
    }

    @Test
    public void getSSLInfo_returnsSSLInfoWithProtocolAndCipher_whenNoClientAuthRequired() throws Exception {
        SSLSession session = mock(SSLSession.class);
        when(session.getProtocol()).thenReturn("TLSv1.3");
        when(session.getCipherSuite()).thenReturn("TLS_AES_256_GCM_SHA384");
        when(session.getLocalCertificates()).thenReturn(null);

        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getSession()).thenReturn(session);
        when(engine.getNeedClientAuth()).thenReturn(false);
        when(engine.getWantClientAuth()).thenReturn(false);

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.getSSLEngine()).thenReturn(engine);

        SSLRequestHelper.SSLInfo info = SSLRequestHelper.getSSLInfo(Settings.EMPTY, sslDir(), request, null);

        assertThat(info, is(notNullValue()));
        assertThat(info.getProtocol(), is("TLSv1.3"));
        assertThat(info.getCipher(), is("TLS_AES_256_GCM_SHA384"));
        assertThat(info.getX509Certs(), is(nullValue()));
        assertThat(info.getLocalCertificates(), is(nullValue()));
        assertThat(info.getPrincipal(), is(nullValue()));
    }

    @Test
    public void getSSLInfo_throwsOpenSearchException_whenNeedClientAuth_andNoPeerCertificates() throws Exception {
        SSLSession session = mock(SSLSession.class);
        when(session.getProtocol()).thenReturn("TLSv1.3");
        when(session.getCipherSuite()).thenReturn("TLS_AES_256_GCM_SHA384");
        when(session.getPeerCertificates()).thenThrow(new SSLPeerUnverifiedException("no peer cert"));

        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getSession()).thenReturn(session);
        when(engine.getNeedClientAuth()).thenReturn(true);
        when(engine.getWantClientAuth()).thenReturn(false);

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.getSSLEngine()).thenReturn(engine);

        try {
            SSLRequestHelper.getSSLInfo(Settings.EMPTY, sslDir(), request, null);
            fail("Expected OpenSearchException when no client certificate is present");
        } catch (OpenSearchException e) {
            assertThat(e.getMessage(), containsString("No client certificates found"));
        }
    }

    @Test
    public void getSSLInfo_returnsX509Certs_whenClientCertProvided() throws Exception {
        // Use a real certificate loaded from test resources; only the SSL plumbing is mocked.
        X509Certificate[] clientCerts = loadCerts("ssl/crl/revoked.crt.pem");

        SSLSession session = mock(SSLSession.class);
        when(session.getProtocol()).thenReturn("TLSv1.3");
        when(session.getCipherSuite()).thenReturn("TLS_AES_256_GCM_SHA384");
        when(session.getPeerCertificates()).thenReturn(clientCerts);
        when(session.getLocalCertificates()).thenReturn(null);

        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getSession()).thenReturn(session);
        when(engine.getNeedClientAuth()).thenReturn(true);
        when(engine.getWantClientAuth()).thenReturn(false);

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.getSSLEngine()).thenReturn(engine);

        // CRL validation disabled so we only test the cert-extraction path
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, false).build();

        SSLRequestHelper.SSLInfo info = SSLRequestHelper.getSSLInfo(settings, sslDir(), request, null);

        assertThat(info, is(notNullValue()));
        assertThat(info.getX509Certs(), is(notNullValue()));
        assertThat(info.getX509Certs().length, is(clientCerts.length));
        assertThat(info.getPrincipal(), is(nullValue()));
    }

    @Test
    public void getSSLInfo_populatesLocalCertificates_whenSessionProvidesLocalCerts() throws Exception {
        X509Certificate[] localCerts = loadCerts("ssl/node-0.crt.pem");

        SSLSession session = mock(SSLSession.class);
        when(session.getProtocol()).thenReturn("TLSv1.3");
        when(session.getCipherSuite()).thenReturn("TLS_AES_256_GCM_SHA384");
        when(session.getLocalCertificates()).thenReturn(localCerts);

        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getSession()).thenReturn(session);
        when(engine.getNeedClientAuth()).thenReturn(false);
        when(engine.getWantClientAuth()).thenReturn(false);

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.getSSLEngine()).thenReturn(engine);

        SSLRequestHelper.SSLInfo info = SSLRequestHelper.getSSLInfo(Settings.EMPTY, sslDir(), request, null);

        assertThat(info, is(notNullValue()));
        assertThat(info.getLocalCertificates(), is(notNullValue()));
        assertThat(info.getLocalCertificates().length, is(localCerts.length));
        assertThat(info.getLocalCertificates()[0], is(localCerts[0]));
    }
}
