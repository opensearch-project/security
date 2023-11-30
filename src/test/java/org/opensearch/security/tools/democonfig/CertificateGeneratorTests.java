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
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.tools.democonfig.util.NoExitSecurityManager;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
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

            String fileContents = null;
            try {
                fileContents = new String(Files.readAllBytes(Path.of(certFilePath)));
            } catch (Exception e) {
                fail("Expected the test to pass.");
            }

            assertThat(fileContents.isEmpty(), not(true));
            assertThat(fileContents, containsString("---BEGIN"));
            assertThat(fileContents, containsString("---END"));
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
}
