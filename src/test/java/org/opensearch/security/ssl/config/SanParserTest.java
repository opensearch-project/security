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

import java.io.InputStream;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.junit.Assume;
import org.junit.Test;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.opensearch.security.test.helper.file.FileHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

public class SanParserTest {

    // ssl/reload/node.crt.pem contains SAN extension: [Other-Name: Unrecognized ObjectIdentifier: 2.5.4.3]
    private static final String CERT_RESOURCE = "ssl/reload/node.crt.pem";
    private static final String EXPECTED_OID = "2.5.4.3";
    private static final String EXPECTED_VALUE = "node-1.example.com";

    @Test
    public void parseOtherNameSan_providerAgnostic() throws Exception {
        X509Certificate jdkCert = loadCert(CertificateFactory.getInstance("X.509", "SUN"));
        X509Certificate bcCert = loadCert(CertificateFactory.getInstance("X.509", "BCFIPS"));
        String sansJdk = SanParser.parse(jdkCert);
        String sansBc = SanParser.parse(bcCert);
        assertThat(sansJdk, containsString(EXPECTED_OID));
        assertThat(sansJdk, containsString(EXPECTED_VALUE));
        assertThat(sansJdk, equalTo(sansBc));
    }

    @Test
    public void badIpSan_fipsMode_throwsRuntimeException() throws Exception {
        Assume.assumeTrue(CryptoServicesRegistrar.isInApprovedOnlyMode());
        X509Certificate x509 = buildCertWithBadIpSan();
        RuntimeException ex = assertThrows(RuntimeException.class, () -> SanParser.parse(x509));
        assertThat(ex.getCause(), instanceOf(UnknownHostException.class));
    }

    @Test
    public void badIpSan_nonFipsMode_returnsEmpty() throws Exception {
        Assume.assumeFalse(CryptoServicesRegistrar.isInApprovedOnlyMode());
        assertThat(SanParser.parse(buildCertWithBadIpSan()), is(""));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /** Builds a self-signed cert with a 3-byte iPAddress SAN (invalid: must be 4 or 16 bytes). */
    private static X509Certificate buildCertWithBadIpSan() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name dn = new X500Name("CN=test");
        Date now = new Date();
        GeneralName badIp = new GeneralName(GeneralName.iPAddress, new DEROctetString(new byte[] { 1, 2, 3 }));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            dn,
            BigInteger.ONE,
            now,
            new Date(now.getTime() + 86_400_000L),
            dn,
            kp.getPublic()
        );
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(badIp));
        ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static X509Certificate loadCert(CertificateFactory factory) throws Exception {
        try (InputStream in = Files.newInputStream(FileHelper.getAbsoluteFilePathFromClassPath(CERT_RESOURCE))) {
            return (X509Certificate) factory.generateCertificate(in);
        }
    }
}
