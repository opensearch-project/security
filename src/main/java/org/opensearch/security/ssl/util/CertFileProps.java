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

package org.opensearch.security.ssl.util;

public class CertFileProps {
    private final String pemCertFilePath;
    private final String pemKeyFilePath;
    private final String trustedCasFilePath;
    private final String pemKeyPassword;

    public CertFileProps(String pemCertFilePath, String pemKeyFilePath, String trustedCasFilePath, String pemKeyPassword) {
        this.pemCertFilePath = pemCertFilePath;
        this.pemKeyFilePath = pemKeyFilePath;
        this.trustedCasFilePath = trustedCasFilePath;
        this.pemKeyPassword = pemKeyPassword;
    }

    public String getPemCertFilePath() {
        return pemCertFilePath;
    }

    public String getPemKeyFilePath() {
        return pemKeyFilePath;
    }

    public String getTrustedCasFilePath() {
        return trustedCasFilePath;
    }

    public String getPemKeyPassword() {
        return pemKeyPassword;
    }
}
