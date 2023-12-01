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

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.util.Date;
import java.util.TimeZone;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.tools.democonfig.util.NoExitSecurityManager;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_CONF_DIR;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.junit.Assert.fail;

public class CertificateGeneratorTests {

    @Before
    public void setUp() {
        OPENSEARCH_CONF_DIR = System.getProperty("user.dir") + File.separator + "test-conf";
        createDirectory(OPENSEARCH_CONF_DIR);
    }

    @After
    public void tearDown() {
        deleteDirectoryRecursive(OPENSEARCH_CONF_DIR);
    }

    @Test
    public void testCreateDemoCertificates() {
        CertificateGenerator certificateGenerator = new CertificateGenerator();
        Certificates[] certificatesArray = Certificates.values();

        certificateGenerator.createDemoCertificates();

        for (Certificates cert : certificatesArray) {
            String certFilePath = OPENSEARCH_CONF_DIR + File.separator + cert.getFileName();
            File certFile = new File(certFilePath);
            assertThat(certFile.exists(), is(equalTo(true)));
            assertThat(certFile.canRead(), is(equalTo(true)));

            checkCertificateValidity(certFilePath);
        }
    }

    @Test
    public void testCreateDemoCertificates_invalidPath() {
        OPENSEARCH_CONF_DIR = "invalidPath";
        CertificateGenerator certificateGenerator = new CertificateGenerator();
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
}
