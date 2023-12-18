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
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * This class creates demo certificate files
 */
public class CertificateGenerator {

    private final Installer installer;

    public CertificateGenerator(Installer installer) {
        this.installer = installer;
    }

    /**
     * Creates demo super-admin, node and root certificates by iterating through Certificates enum
     */
    public void createDemoCertificates() {
        for (Certificates cert : Certificates.values()) {
            String filePath = this.installer.OPENSEARCH_CONF_DIR + File.separator + cert.getFileName();
            writeCertificateToFile(filePath, cert.getContent());
        }
    }

    /**
     * Helper method to write the certificates to their own file
     * @param filePath the file which needs to be written
     * @param content the content which needs to be written to this file
     */
    static void writeCertificateToFile(String filePath, String content) {
        try {
            FileWriter fileWriter = new FileWriter(filePath, StandardCharsets.UTF_8);
            fileWriter.write(content);
            fileWriter.close();
        } catch (IOException e) {
            System.err.println("Error writing certificate file: " + filePath);
            System.exit(-1);
        }
    }
}
