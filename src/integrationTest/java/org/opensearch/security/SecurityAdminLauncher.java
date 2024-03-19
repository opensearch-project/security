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
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.opensearch.security.tools.SecurityAdmin;
import org.opensearch.test.framework.certificate.TestCertificates;

import static java.util.Objects.requireNonNull;

class SecurityAdminLauncher {

    private final TestCertificates certificates;
    private int port;

    public SecurityAdminLauncher(int port, TestCertificates certificates) {
        this.port = port;
        this.certificates = requireNonNull(certificates, "Certificates are required to communicate with cluster.");
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
                "-f",
                roleMappingsConfigurationFile.getAbsolutePath(),
                "-t",
                "rolesmapping" };

        return SecurityAdmin.execute(commandLineArguments);
    }

    public Set<String> listFilesUsingJavaIO(String dir) {
        return Stream.of(new File(dir).listFiles())
                .filter(file -> !file.isDirectory())
                .map(File::getName)
                .collect(Collectors.toSet());
    }

    public int runSecurityAdmin(Path configurationFolder) throws Exception {
        System.out.println("configurationFolder: " + configurationFolder);
        System.out.println("configFiles: " + listFilesUsingJavaIO(configurationFolder.toString()));
        String[] commandLineArguments = {
                "-cacert",
                certificates.getRootCertificate().getAbsolutePath(),
                "-cert",
                certificates.getAdminCertificate().getAbsolutePath(),
                "-key",
                certificates.getAdminKey(null).getAbsolutePath(),
                "-nhnv",
                "-icl",
                "-p",
                String.valueOf(port),
                "-cd",
                configurationFolder.toString(),
                "--diagnose"};

        return SecurityAdmin.execute(commandLineArguments);
    }
}