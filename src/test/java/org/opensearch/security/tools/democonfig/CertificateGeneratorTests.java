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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.junit.Assert.fail;

/**
 * Tests for the CertificateGenerator.
 */
public class CertificateGeneratorTests {

    private static Installer installer;

    // Custom exception to simulate an exit via the exit handler.
    public static class TestExitException extends RuntimeException {
        private final int status;

        public TestExitException(int status) {
            super("Exit code " + status);
            this.status = status;
        }

        public int getStatus() {
            return status;
        }
    }

    @Before
    public void setUp() {
        installer = Installer.getInstance();
        installer.buildOptions();
        installer.OPENSEARCH_CONF_DIR = System.getProperty("user.dir") + File.separator + "test-conf";
        createDirectory(installer.OPENSEARCH_CONF_DIR);
    }

    @After
    public void tearDown() {
        deleteDirectoryRecursive(installer.OPENSEARCH_CONF_DIR);
        Installer.resetInstance();
    }

    @Test
    public void testCreateDemoCertificates() throws Exception {
        CertificateGenerator certificateGenerator = new CertificateGenerator(installer);
        Certificates[] certificatesArray = Certificates.values();

        certificateGenerator.createDemoCertificates();

        // Expect five certificate files: root-ca.pem, esnode.pem, esnode-key.pem, kirk.pem, kirk-key.pem
        int expectedNumberOfCertificateFiles = 5;
        int certsFound = 0;

        for (Certificates cert : certificatesArray) {
            String certFilePath = installer.OPENSEARCH_CONF_DIR + File.separator + cert.getFileName();
            File certFile = new File(certFilePath);
            assertThat(certFile.exists(), is(equalTo(true)));
            assertThat(certFile.canRead(), is(equalTo(true)));

            if (certFilePath.endsWith("-key.pem")) {
                checkPrivateKeyValidity(certFilePath);
            } else {
                checkCertificateValidity(certFilePath);
            }
            certsFound++;  // count valid file
        }

        assertThat(certsFound, equalTo(expectedNumberOfCertificateFiles));
    }

    @Test
    public void testCreateDemoCertificates_invalidPath() {
        // Use an invalid directory path so that certificate creation fails
        installer.OPENSEARCH_CONF_DIR = "invalidPath";
        CertificateGenerator certificateGenerator = new CertificateGenerator(installer);
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        try {
            certificateGenerator.createDemoCertificates();
            fail("Expected exit handler to be invoked");
        } catch (TestExitException e) {
            assertThat(e.getStatus(), equalTo(-1));
        }
    }

    private static void checkCertificateValidity(String certPath) throws Exception {
        try (FileInputStream certInputStream = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate certificate = cf.generateCertificate(certInputStream);

            if (certificate instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                Date expiryDate = x509Certificate.getNotAfter();
                Instant expiry = expiryDate.toInstant();

                Period duration = getPeriodBetween(x509Certificate.getNotBefore().toInstant(), expiry);

                // Check that certificate lifetime is roughly 10 years (9 years and 11 months)
                assertThat(duration.getYears(), equalTo(9));
                assertThat(duration.getMonths(), equalTo(11));

                // Ensure certificate is currently valid and will remain valid at least one year from now
                x509Certificate.checkValidity();
                verifyExpiryAtLeastAYearFromNow(expiry);

                assertThat(x509Certificate.getSigAlgName(), is(equalToIgnoringCase("SHA256withRSA")));
            }
        }
    }

    private static void verifyExpiryAtLeastAYearFromNow(Instant expiry) {
        Period gap = getPeriodBetween(Instant.now(), expiry);
        assertThat(gap.getYears(), greaterThanOrEqualTo(1));
    }

    private static Period getPeriodBetween(Instant start, Instant end) {
        LocalDate startDate = LocalDate.ofInstant(start, TimeZone.getTimeZone("EDT").toZoneId());
        LocalDate endDate = LocalDate.ofInstant(end, TimeZone.getTimeZone("EDT").toZoneId());
        return Period.between(startDate, endDate);
    }

    private void checkPrivateKeyValidity(String keyPath) {
        try {
            String pemContent = readPEMFile(keyPath);
            // Remove the BEGIN/END markers and whitespace
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
                pemContent.append(line);
            }
        }
        return pemContent.toString();
    }
}
