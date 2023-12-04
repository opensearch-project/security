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

package org.opensearch.security.tools.democonfig;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.tools.democonfig.util.NoExitSecurityManager;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.junit.Assert.fail;

public class CertificateGeneratorTests {

    private static Installer installer;

    @Before
    public void setUp() {
        installer = Installer.getInstance();
        installer.OPENSEARCH_CONF_DIR = System.getProperty("user.dir") + File.separator + "test-conf";
        createDirectory(installer.OPENSEARCH_CONF_DIR);
    }

    @After
    public void tearDown() {

        deleteDirectoryRecursive(installer.OPENSEARCH_CONF_DIR);
        Installer.resetInstance();
    }

    @Test
    public void testCreateDemoCertificates() {
        CertificateGenerator certificateGenerator = new CertificateGenerator(installer);
        Certificates[] certificatesArray = Certificates.values();

        certificateGenerator.createDemoCertificates();

        for (Certificates cert : certificatesArray) {
            String certFilePath = installer.OPENSEARCH_CONF_DIR + File.separator + cert.getFileName();
            File certFile = new File(certFilePath);
            assertThat(certFile.exists(), is(equalTo(true)));
            assertThat(certFile.canRead(), is(equalTo(true)));

            if (certFilePath.endsWith("-key.pem")) {
                checkPrivateKeyValidity(certFilePath);
                return;
            }
            checkCertificateValidity(certFilePath);
        }
    }

    @Test
    public void testCreateDemoCertificates_invalidPath() {
        installer.OPENSEARCH_CONF_DIR = "invalidPath";
        CertificateGenerator certificateGenerator = new CertificateGenerator(installer);
        try {
            System.setSecurityManager(new NoExitSecurityManager());
            certificateGenerator.createDemoCertificates();
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    private static void checkCertificateValidity(String certPath) {
        try (FileInputStream certInputStream = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate certificate = cf.generateCertificate(certInputStream);

            if (certificate instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                x509Certificate.checkValidity();

                Date expiryDate = x509Certificate.getNotAfter();
                Instant expiry = expiryDate.toInstant();

                assertThat(isExpiryAtLeastAYearLater(expiry), is(equalTo(true)));
                assertThat(x509Certificate.getSigAlgName(), is(equalTo("SHA256withRSA")));
            } else {
                fail("Certificate is invalid. Expected X.509 certificate.");
            }
        } catch (Exception e) {
            fail("Error checking certificate validity: " + e.getMessage());
        }
    }

    private static boolean isExpiryAtLeastAYearLater(Instant expiry) {
        Instant currentInstant = Instant.now();
        LocalDate expiryDate = LocalDate.ofInstant(expiry, TimeZone.getTimeZone("EDT").toZoneId());
        LocalDate currentDate = LocalDate.ofInstant(currentInstant, TimeZone.getTimeZone("EDT").toZoneId());

        Period gap = Period.between(currentDate, expiryDate);
        return gap.getYears() >= 1;
    }

    private void checkPrivateKeyValidity(String keyPath) {
        try {
            String pemContent = readPEMFile(keyPath);

            String base64Data = pemContent.replaceAll("-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----", "").replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(base64Data);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            assertThat(key.getFormat(), is(equalTo("PKCS#8")));
            assertThat(key.getAlgorithm(), is(equalTo("RSA")));
            assertThat(key.isDestroyed(), is(equalTo(false)));
        } catch (Exception e) {
            fail("Error checking key validity: " + e.getMessage());
        }
    }

    private static String readPEMFile(String pemFilePath) throws Exception {
        StringBuilder pemContent = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(pemFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                pemContent.append(line).append("\n");
            }
        }
        return pemContent.toString();
    }
}
