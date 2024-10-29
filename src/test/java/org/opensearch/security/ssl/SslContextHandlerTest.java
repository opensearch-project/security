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

package org.opensearch.security.ssl;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.config.KeyStoreConfiguration;
import org.opensearch.security.ssl.config.SslParameters;
import org.opensearch.security.ssl.config.TrustStoreConfiguration;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.CertificatesUtils.privateKeyToPemObject;
import static org.opensearch.security.ssl.CertificatesUtils.writePemContent;
import static org.junit.Assert.assertThrows;

public class SslContextHandlerTest {

    @ClassRule
    public static CertificatesRule certificatesRule = new CertificatesRule();

    Path caCertificatePath;

    Path accessCertificatePath;

    Path accessCertificatePrivateKeyPath;

    @Before
    public void setUp() throws Exception {
        caCertificatePath = certificatesRule.configRootFolder().resolve("ca_certificate.pem");
        accessCertificatePath = certificatesRule.configRootFolder().resolve("access_certificate.pem");
        accessCertificatePrivateKeyPath = certificatesRule.configRootFolder().resolve("access_certificate_pk.pem");
        writeCertificates(
            certificatesRule.caCertificateHolder(),
            certificatesRule.accessCertificateHolder(),
            certificatesRule.accessCertificatePrivateKey()
        );
    }

    void writeCertificates(
        final X509CertificateHolder caCertificate,
        final X509CertificateHolder accessCertificate,
        final PrivateKey accessPrivateKey
    ) throws Exception {
        writePemContent(caCertificatePath, caCertificate);
        writePemContent(accessCertificatePath, accessCertificate);
        writePemContent(accessCertificatePrivateKeyPath, privateKeyToPemObject(accessPrivateKey, certificatesRule.privateKeyPassword()));
    }

    @Test
    public void doesNothingIfCertificatesAreSame() throws Exception {
        final var sslContextHandler = sslContextHandler();

        final var sslContextBefore = sslContextHandler.sslContext();
        sslContextHandler.reloadSslContext();

        assertThat("SSL Context is the same", sslContextBefore.equals(sslContextHandler.sslContext()));
    }

    @Test
    public void failsIfAuthorityCertificateHasInvalidDates() throws Exception {
        final var sslContextHandler = sslContextHandler();
        final var keyPair = certificatesRule.generateKeyPair();

        final var caCertificate = certificatesRule.caCertificateHolder();

        var newCaCertificate = certificatesRule.generateCaCertificate(
            keyPair,
            caCertificate.getNotAfter().toInstant(),
            caCertificate.getNotAfter().toInstant().minus(10, ChronoUnit.DAYS)
        );

        writeCertificates(newCaCertificate, certificatesRule.accessCertificateHolder(), certificatesRule.accessCertificatePrivateKey());

        assertThrows(CertificateException.class, sslContextHandler::reloadSslContext);

        newCaCertificate = certificatesRule.generateCaCertificate(
            keyPair,
            caCertificate.getNotBefore().toInstant().plus(10, ChronoUnit.DAYS),
            caCertificate.getNotAfter().toInstant().plus(20, ChronoUnit.DAYS)
        );
        writeCertificates(newCaCertificate, certificatesRule.accessCertificateHolder(), certificatesRule.accessCertificatePrivateKey());

        assertThrows(CertificateException.class, sslContextHandler::reloadSslContext);
    }

    @Test
    public void failsIfKeyMaterialCertificateHasInvalidDates() throws Exception {
        final var sslContextHandler = sslContextHandler();

        final var accessCertificate = certificatesRule.x509AccessCertificate();
        final var keyPair = certificatesRule.generateKeyPair();
        final var newCaCertificate = certificatesRule.generateCaCertificate(keyPair);
        var newAccessCertificate = certificatesRule.generateAccessCertificate(
            keyPair,
            accessCertificate.getNotBefore().toInstant(),
            accessCertificate.getNotAfter().toInstant().minus(10, ChronoUnit.DAYS)
        );

        writeCertificates(newCaCertificate, newAccessCertificate.v2(), newAccessCertificate.v1());

        assertThrows(CertificateException.class, sslContextHandler::reloadSslContext);

        newAccessCertificate = certificatesRule.generateAccessCertificate(
            keyPair,
            accessCertificate.getNotBefore().toInstant().plus(10, ChronoUnit.DAYS),
            accessCertificate.getNotAfter().toInstant().plus(20, ChronoUnit.DAYS)
        );
        writeCertificates(newCaCertificate, newAccessCertificate.v2(), newAccessCertificate.v1());

        assertThrows(CertificateException.class, sslContextHandler::reloadSslContext);
    }

    @Test
    public void failsIfKeyMaterialCertificateHasNotValidSubjectDNs() throws Exception {
        final var sslContextHandler = sslContextHandler();

        final var keyPair = certificatesRule.generateKeyPair();
        final var newCaCertificate = certificatesRule.generateCaCertificate(keyPair);
        final var currentAccessCertificate = certificatesRule.x509AccessCertificate();
        final var wrongSubjectAccessCertificate = certificatesRule.generateAccessCertificate(
            keyPair,
            "CN=ddddd,O=client,L=test,C=de",
            currentAccessCertificate.getIssuerX500Principal().getName()
        );

        writeCertificates(newCaCertificate, wrongSubjectAccessCertificate.v2(), wrongSubjectAccessCertificate.v1());

        final var e = assertThrows(CertificateException.class, sslContextHandler::reloadSslContext);
        assertThat(
            e.getMessage(),
            is(
                "New certificates do not have valid Subject DNs. "
                    + "Current Subject DNs [CN=some_access,OU=client,O=client,L=test,C=de] "
                    + "new Subject DNs [CN=ddddd,O=client,L=test,C=de]"
            )
        );
    }

    @Test
    public void failsIfKeyMaterialCertificateHasNotValidIssuerDNs() throws Exception {
        final var sslContextHandler = sslContextHandler();

        final var keyPair = certificatesRule.generateKeyPair();
        final var newCaCertificate = certificatesRule.generateCaCertificate(keyPair);
        final var currentAccessCertificate = certificatesRule.x509AccessCertificate();
        final var wrongSubjectAccessCertificate = certificatesRule.generateAccessCertificate(
            keyPair,
            currentAccessCertificate.getSubjectX500Principal().getName(),
            "CN=ddddd,O=client,L=test,C=de"
        );

        writeCertificates(newCaCertificate, wrongSubjectAccessCertificate.v2(), wrongSubjectAccessCertificate.v1());

        final var e = assertThrows(CertificateException.class, sslContextHandler::reloadSslContext);
        assertThat(
            e.getMessage(),
            is(
                "New certificates do not have valid Issuer DNs. "
                    + "Current Issuer DNs: [CN=some_access,OU=client,O=client,L=test,C=de] "
                    + "new Issuer DNs: [CN=ddddd,O=client,L=test,C=de]"
            )
        );
    }

    @Test
    public void failsIfKeyMaterialCertificateHasNotValidSans() throws Exception {
        final var sslContextHandler = sslContextHandler();

        final var keyPair = certificatesRule.generateKeyPair();
        final var newCaCertificate = certificatesRule.generateCaCertificate(keyPair);
        final var wrongSubjectAccessCertificate = certificatesRule.generateAccessCertificate(
            keyPair,
            List.of(new GeneralName(GeneralName.iPAddress, "127.0.0.3"))
        );

        writeCertificates(newCaCertificate, wrongSubjectAccessCertificate.v2(), wrongSubjectAccessCertificate.v1());

        final var e = assertThrows(CertificateException.class, sslContextHandler::reloadSslContext);
        assertThat(
            e.getMessage(),
            is(
                "New certificates do not have valid SANs. "
                    + "Current SANs: [[[2, localhost], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]] "
                    + "new SANs: [[[7, 127.0.0.3]]]"
            )
        );
    }

    @Test
    public void reloadSslContext() throws Exception {
        final var sslContextHandler = sslContextHandler();

        final var sslContextBefore = sslContextHandler.sslContext();

        final var keyPair = certificatesRule.generateKeyPair();
        final var newCaCertificate = certificatesRule.generateCaCertificate(keyPair);
        final var currentAccessCertificate = certificatesRule.x509AccessCertificate();
        final var newAccessCertificate = certificatesRule.generateAccessCertificate(
            keyPair,
            currentAccessCertificate.getNotBefore().toInstant(),
            currentAccessCertificate.getNotAfter().toInstant().plus(10, ChronoUnit.MINUTES)
        );

        writeCertificates(newCaCertificate, newAccessCertificate.v2(), newAccessCertificate.v1());

        sslContextHandler.reloadSslContext();

        assertThat("Context reloaded", is(not(sslContextBefore.equals(sslContextHandler.sslContext()))));
    }

    @Test
    public void reloadSslContextForShuffledSameSans() throws Exception {
        final var sslContextHandler = sslContextHandler();

        final var sslContextBefore = sslContextHandler.sslContext();

        final var keyPair = certificatesRule.generateKeyPair();
        final var newCaCertificate = certificatesRule.generateCaCertificate(keyPair);
        final var currentAccessCertificate = certificatesRule.accessCertificateHolder();

        // CS-SUPPRESS-SINGLE: RegexpSingleline Extension should only be used sparingly to keep implementations as generic as possible
        final var newAccessCertificate = certificatesRule.generateAccessCertificate(
            keyPair,
            currentAccessCertificate.getNotBefore().toInstant(),
            currentAccessCertificate.getNotAfter().toInstant().plus(10, ChronoUnit.MINUTES),
            shuffledSans(currentAccessCertificate.getExtension(Extension.subjectAlternativeName))
        );
        // CS-ENFORCE-SINGLE

        writeCertificates(newCaCertificate, newAccessCertificate.v2(), newAccessCertificate.v1());

        sslContextHandler.reloadSslContext();

        assertThat("Context reloaded", is(not(sslContextBefore.equals(sslContextHandler.sslContext()))));
    }

    // CS-SUPPRESS-SINGLE: RegexpSingleline Extension should only be used sparingly to keep implementations as generic as possible
    List<ASN1Encodable> shuffledSans(Extension currentSans) {
        final var san1Sequence = ASN1Sequence.getInstance(currentSans.getParsedValue().toASN1Primitive());

        final var shuffledSans = new ArrayList<ASN1Encodable>();
        final var objects = san1Sequence.getObjects();
        while (objects.hasMoreElements()) {
            shuffledSans.add(GeneralName.getInstance(objects.nextElement()));
        }

        for (int i = 0; i < 5; i++)
            Collections.shuffle(shuffledSans);
        return shuffledSans;
    }
    // CS-ENFORCE-SINGLE

    SslContextHandler sslContextHandler() {
        final var sslParameters = SslParameters.loader(Settings.EMPTY).load(false);
        final var trustStoreConfiguration = new TrustStoreConfiguration.PemTrustStoreConfiguration(caCertificatePath);
        final var keyStoreConfiguration = new KeyStoreConfiguration.PemKeyStoreConfiguration(
            accessCertificatePath,
            accessCertificatePrivateKeyPath,
            certificatesRule.privateKeyPassword().toCharArray()
        );

        SslConfiguration sslConfiguration = new SslConfiguration(sslParameters, trustStoreConfiguration, keyStoreConfiguration);
        return new SslContextHandler(sslConfiguration, false);
    }

}
