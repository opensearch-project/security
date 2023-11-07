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

package com.amazon.dlic.auth.http.saml;

import java.io.File;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;

import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;

public class SamlFilesystemMetadataResolver extends FilesystemMetadataResolver {

    SamlFilesystemMetadataResolver(String filePath, Settings opensearchSettings, Path configPath) throws Exception {
        super(getMetadataFile(filePath, opensearchSettings, configPath));
    }

    @Override
    @SuppressWarnings("removal")
    protected byte[] fetchMetadata() throws ResolverException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<byte[]>() {
                @Override
                public byte[] run() throws ResolverException {
                    return SamlFilesystemMetadataResolver.super.fetchMetadata();
                }
            });
        } catch (PrivilegedActionException e) {

            if (e.getCause() instanceof ResolverException) {
                throw (ResolverException) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private static File getMetadataFile(String filePath, Settings settings, Path configPath) {
        Environment env = new Environment(settings, configPath);
        return env.configFile().resolve(filePath).toAbsolutePath().toFile();
    }
}
