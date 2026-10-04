/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.io.File;
import java.nio.file.Path;

import org.opensearch.security.tools.SecurityAdmin;
import org.opensearch.test.framework.certificate.TestCertificates;

import static java.util.Objects.requireNonNull;

class SecurityAdminLauncher {

    private final TestCertificates certificates;
    private final String clusterName;
    private int port;

    public SecurityAdminLauncher(int port, TestCertificates certificates, String clusterName) {
        this.port = port;
        this.certificates = requireNonNull(certificates, "Certificates are required to communicate with cluster.");
        this.clusterName = requireNonNull(clusterName, "Cluster name is required.");
    }

    public int updateRoleMappings(File roleMappingsConfigurationFile) throws Exception {
        String[] commandLineArguments = {
            "-cacert",
            certificates.getRootCertificate().getAbsolutePath(),
            "-cert",
            certificates.getAdminCertificate().getAbsolutePath(),
            "-key",
            certificates.getAdminKey(null).getAbsolutePath(),
            "-nhnv",
            "-p",
            String.valueOf(port),
            "-cn",
            clusterName,
            "-f",
            roleMappingsConfigurationFile.getAbsolutePath(),
            "-t",
            "rolesmapping" };

        return SecurityAdmin.execute(commandLineArguments);
    }

    public int runSecurityAdmin(Path configurationFolder) throws Exception {
        String[] commandLineArguments = {
            "-cacert",
            certificates.getRootCertificate().getAbsolutePath(),
            "-cert",
            certificates.getAdminCertificate().getAbsolutePath(),
            "-key",
            certificates.getAdminKey(null).getAbsolutePath(),
            "-nhnv",
            "-p",
            String.valueOf(port),
            "-cn",
            clusterName,
            "-cd",
            configurationFolder.toString() };

        return SecurityAdmin.execute(commandLineArguments);
    }

    public int backup(Path backupFolder) throws Exception {
        String[] commandLineArguments = {
            "-cacert",
            certificates.getRootCertificate().getAbsolutePath(),
            "-cert",
            certificates.getAdminCertificate().getAbsolutePath(),
            "-key",
            certificates.getAdminKey(null).getAbsolutePath(),
            "-nhnv",
            "-p",
            String.valueOf(port),
            "-cn",
            clusterName,
            "-backup",
            backupFolder.toString() };

        return SecurityAdmin.execute(commandLineArguments);
    }
}
