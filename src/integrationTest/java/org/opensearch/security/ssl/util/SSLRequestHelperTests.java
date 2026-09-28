/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManagerFactory;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.certificate.TestCertificates;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_PASSWORD;
import static org.junit.Assert.assertThrows;

public class SSLRequestHelperTests {

    private static final String STORE_NAME = CryptoServicesRegistrar.isInApprovedOnlyMode() ? "truststore.bcfks" : "truststore.jks";
    private static final String STORE_TYPE = CryptoServicesRegistrar.isInApprovedOnlyMode() ? "BCFKS" : "JKS";
    private static final char[] INTERNAL_STORE_PASSWORD = DEFAULT_STORE_PASSWORD.toCharArray();

    /** Minimum TLS packet buffer size used when the engine reports a smaller value. */
    private static final int MIN_NET_BUFFER_SIZE = 32_768;
    /** Minimum TLS application buffer size used when the engine reports a smaller value. */
    private static final int MIN_APP_BUFFER_SIZE = 4_096;
    /** Maximum handshake loop iterations before giving up. */
    private static final int MAX_HANDSHAKE_ITERATIONS = 200;
    /** CRL validity window written by {@link #writeCrl}. */
    private static final long CRL_VALIDITY_MS = 24 * 60 * 60 * 1_000L;

    @ClassRule
    public static TemporaryFolder tempFolder = new TemporaryFolder();
    /** Resolved root of {@link #tempFolder}. */
    private static Path configDir;
    /** One CA + node-0 (server) + admin (client). Shared across all tests. */
    private static TestCertificates certs;

    @BeforeClass
    public static void setUpCerts() throws Exception {
        certs = new TestCertificates();
        TestCertificates wrongCerts = new TestCertificates();

        configDir = tempFolder.getRoot().toPath();

        Files.copy(certs.getRootCertificate().toPath(), configDir.resolve("ca.pem"));
        Files.copy(wrongCerts.getRootCertificate().toPath(), configDir.resolve("wrong-ca.pem"));

        writeCrl(certs.getRootCertificateData(), configDir.resolve("empty.crl"));
        writeCrl(certs.getRootCertificateData(), configDir.resolve("revoked.crl"), certs.getAdminCertificateData().certificate());
        writeTruststore(certs.getRootCertificateData().certificate(), configDir.resolve(STORE_NAME));
    }

    // ── SSLContext helpers ────────────────────────────────────────────────────

    private static SSLContext buildContext(CertificateData identity, TestCertificates trustSource) throws Exception {
        KeyStore ks = PemKeyReader.toKeystore(
            "identity",
            DEFAULT_STORE_PASSWORD.toCharArray(),
            new java.security.cert.X509Certificate[] { identity.certificate() },
            (PrivateKey) identity.getKey()
        );
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, DEFAULT_STORE_PASSWORD.toCharArray());

        KeyStore ts = PemKeyReader.toTruststore("ca", PemKeyReader.loadCertificatesFromFile(trustSource.getRootCertificate()));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    // ── Handshake engine ──────────────────────────────────────────────────────

    /** Returns a post-handshake server engine using node-0 as server and admin cert as client. */
    private static SSLEngine handshake() throws Exception {
        return handshake(
            //
            buildContext(certs.getNodeCertificateData(0), certs), //
            buildContext(certs.getAdminCertificateData(), certs) //
        );
    }

    /**
     * Drives a full TLS loopback handshake between two {@link SSLEngine} instances and
     * returns the server-side engine after the handshake completes.
     */
    private static SSLEngine handshake(SSLContext serverCtx, SSLContext clientCtx) throws Exception {
        SSLEngine server = serverCtx.createSSLEngine();
        server.setUseClientMode(false);
        server.setNeedClientAuth(true);

        SSLEngine client = clientCtx.createSSLEngine();
        client.setUseClientMode(true);

        client.beginHandshake();
        server.beginHandshake();

        int netSize = Math.max(server.getSession().getPacketBufferSize(), MIN_NET_BUFFER_SIZE);
        int appSize = Math.max(server.getSession().getApplicationBufferSize(), MIN_APP_BUFFER_SIZE);

        ByteBuffer cToS = ByteBuffer.allocate(netSize * 4);
        ByteBuffer sToC = ByteBuffer.allocate(netSize * 4);
        ByteBuffer app = ByteBuffer.allocate(appSize);

        for (int guard = 0; guard < MAX_HANDSHAKE_ITERATIONS; guard++) {
            runTasks(server);
            runTasks(client);

            if (client.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
                ByteBuffer net = ByteBuffer.allocate(netSize);
                client.wrap(app, net);
                net.flip();
                cToS.put(net);
                runTasks(client);
            }

            if (server.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP && cToS.position() > 0) {
                cToS.flip();
                server.unwrap(cToS, app);
                cToS.compact();
                runTasks(server);
            }

            if (server.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
                ByteBuffer net = ByteBuffer.allocate(netSize);
                server.wrap(app, net);
                net.flip();
                sToC.put(net);
                runTasks(server);
            }

            if (client.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP && sToC.position() > 0) {
                sToC.flip();
                client.unwrap(sToC, app);
                sToC.compact();
                runTasks(client);
            }

            HandshakeStatus ss = server.getHandshakeStatus();
            HandshakeStatus cs = client.getHandshakeStatus();
            if ((ss == HandshakeStatus.FINISHED || ss == HandshakeStatus.NOT_HANDSHAKING) //
                && (cs == HandshakeStatus.FINISHED || cs == HandshakeStatus.NOT_HANDSHAKING)) {
                break;
            }
        }

        return server;
    }

    private static void runTasks(SSLEngine engine) {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    /**
     * Minimal {@link SecurityRequest} that supplies a real {@link SSLEngine} to
     * {@code getSSLInfo}. All other interface methods are unused by {@code getSSLInfo}.
     */
    private static SecurityRequest requestFor(SSLEngine engine) {
        return new SecurityRequest() {
            @Override
            public SSLEngine getSSLEngine() {
                return engine;
            }

            @Override
            public Map<String, List<String>> getHeaders() {
                return Collections.emptyMap();
            }

            @Override
            public String path() {
                return "/";
            }

            @Override
            public Method method() {
                return Method.GET;
            }

            @Override
            public Optional<InetSocketAddress> getRemoteAddress() {
                return Optional.empty();
            }

            @Override
            public String uri() {
                return "/";
            }

            @Override
            public Map<String, String> params() {
                return Collections.emptyMap();
            }

            @Override
            public Set<String> getUnconsumedParams() {
                return Collections.emptySet();
            }
        };
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Writes a truststore of the given {@code type} containing {@code caCert} with no password. */
    private static void writeTruststore(X509Certificate caCert, Path target) throws Exception {
        KeyStore ts = KeyStore.getInstance(STORE_TYPE);
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);
        try (FileOutputStream fos = new FileOutputStream(target.toFile())) {
            ts.store(fos, INTERNAL_STORE_PASSWORD);
        }
    }

    /**
     * Writes a DER-encoded CRL signed by {@code ca}. Each cert in {@code revoked} is added as a
     * revoked entry with reason {@code keyCompromise}. Pass no certs for an empty (no-revocations) CRL.
     */
    private static void writeCrl(CertificateData ca, Path target, X509Certificate... revoked) throws Exception {
        Date now = new Date();

        JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(ca.certificate(), now);
        builder.setNextUpdate(new Date(now.getTime() + CRL_VALIDITY_MS));
        for (X509Certificate cert : revoked) {
            builder.addCRLEntry(cert.getSerialNumber(), now, CRLReason.keyCompromise);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build((PrivateKey) ca.getKey());

        Files.write(target, builder.build(signer).getEncoded());
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    @Test
    public void getSSLInfo_returnsPopulatedSSLInfo_afterHandshakeWithClientAuth() throws Exception {
        SSLEngine serverEngine = handshake();
        Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, false).build();

        SSLRequestHelper.SSLInfo info = SSLRequestHelper.getSSLInfo(settings, configDir, requestFor(serverEngine), null);

        assertThat(info, is(notNullValue()));
        assertThat(info.getX509Certs(), is(notNullValue()));        // peer (admin) certs
        assertThat(info.getLocalCertificates(), is(notNullValue())); // server (node-0) certs
    }

    @Test
    public void getSSLInfo_throwsSSLPeerUnverifiedException_whenCertPathCannotBeBuilt() throws Exception {
        // The peer cert is signed by `certs` CA, but we tell the validator to trust a *different* CA.
        // CertPathBuilder cannot find a valid path → CertPathBuilderException (GeneralSecurityException catch).
        SSLEngine serverEngine = handshake();

        Settings settings = Settings.builder()
            .put("path.home", configDir.getParent().toString())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "wrong-ca.pem")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, true)
            .build();

        SSLPeerUnverifiedException ex = assertThrows(
            SSLPeerUnverifiedException.class,
            () -> SSLRequestHelper.getSSLInfo(settings, configDir, requestFor(serverEngine), null)
        );
        assertThat(ex.getCause(), instanceOf(CertPathBuilderException.class));
    }

    @Test
    public void getSSLInfo_throwsSSLPeerUnverifiedException_whenCrlFileIsMissing() throws Exception {
        // loadCrls throws FileNotFoundException (IOException) when the CRL file does not exist.
        SSLEngine serverEngine = handshake();

        Settings settings = Settings.builder()
            .put("path.home", configDir.getParent().toString())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, "nonexistent.crl")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "ca.pem")
            .build();

        SSLPeerUnverifiedException ex = assertThrows(
            SSLPeerUnverifiedException.class,
            () -> SSLRequestHelper.getSSLInfo(settings, configDir, requestFor(serverEngine), null)
        );
        assertThat(ex.getCause(), instanceOf(FileNotFoundException.class));
    }

    @Test
    public void getSSLInfo_throwsSSLPeerUnverifiedException_whenKeystoreTypeIsInvalid() throws Exception {
        // KeyStore.getInstance("INVALID_TYPE") throws KeyStoreException (GeneralSecurityException).
        SSLEngine serverEngine = handshake();

        Settings settings = Settings.builder()
            .put("path.home", configDir.getParent().toString())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, STORE_NAME)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, "INVALID_TYPE")
            .build();

        SSLPeerUnverifiedException ex = assertThrows(
            SSLPeerUnverifiedException.class,
            () -> SSLRequestHelper.getSSLInfo(settings, configDir, requestFor(serverEngine), null)
        );
        assertThat(ex.getCause(), instanceOf(KeyStoreException.class));
    }

    @Test
    public void getSSLInfo_returnsPopulatedSSLInfo_whenCrlValidationPassesWithEmptyCrl() throws Exception {
        // Happy path with CRL_VALIDATE=true: peer cert is valid, CRL lists no revocations → passes.
        SSLEngine serverEngine = handshake();

        Settings settings = Settings.builder()
            .put("path.home", configDir.getParent().toString())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, "empty.crl")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "ca.pem")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, true)
            .build();

        SSLRequestHelper.SSLInfo info = SSLRequestHelper.getSSLInfo(settings, configDir, requestFor(serverEngine), null);

        assertThat(info, is(notNullValue()));
        assertThat(info.getX509Certs(), is(notNullValue()));
        assertThat(info.getLocalCertificates(), is(notNullValue()));
    }

    @Test
    public void getSSLInfo_throwsSSLPeerUnverifiedException_whenPeerCertIsRevoked() throws Exception {
        // The admin (peer) cert's serial is listed in the CRL → CertPathValidatorException → SSLPeerUnverifiedException.
        SSLEngine serverEngine = handshake();

        Settings settings = Settings.builder()
            .put("path.home", configDir.getParent().toString())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, "revoked.crl")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "ca.pem")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, true)
            .build();

        SSLPeerUnverifiedException ex = assertThrows(
            SSLPeerUnverifiedException.class,
            () -> SSLRequestHelper.getSSLInfo(settings, configDir, requestFor(serverEngine), null)
        );
        assertThat(ex.getCause(), instanceOf(CertPathValidatorException.class));
    }

    @Test
    public void getSSLInfo_returnsPopulatedSSLInfo_whenCrlValidationPassesWithTruststore() throws Exception {
        SSLEngine serverEngine = handshake();

        Settings settings = Settings.builder()
            .put("path.home", configDir.getParent().toString())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE, "empty.crl")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, STORE_NAME)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, STORE_TYPE)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, true)
            .build();

        SSLRequestHelper.SSLInfo info = SSLRequestHelper.getSSLInfo(settings, configDir, requestFor(serverEngine), null);

        assertThat(info, is(notNullValue()));
        assertThat(info.getX509Certs(), is(notNullValue()));
        assertThat(info.getLocalCertificates(), is(notNullValue()));
    }
}
