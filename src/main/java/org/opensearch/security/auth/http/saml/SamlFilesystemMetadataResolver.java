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

package org.opensearch.security.auth.http.saml;

import java.io.File;
import java.nio.file.Path;

import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.secure_sm.AccessController;

import net.shibboleth.shared.resolver.ResolverException;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;

public class SamlFilesystemMetadataResolver extends FilesystemMetadataResolver {

    SamlFilesystemMetadataResolver(String filePath, Settings opensearchSettings, Path configPath) throws Exception {
        super(getMetadataFile(filePath, opensearchSettings, configPath));
    }

    @Override
    protected byte[] fetchMetadata() throws ResolverException {
        return AccessController.doPrivilegedChecked(SamlFilesystemMetadataResolver.super::fetchMetadata);
    }

    private static File getMetadataFile(String filePath, Settings settings, Path configPath) {
        Environment env = new Environment(settings, configPath);
        return env.configDir().resolve(filePath).toAbsolutePath().toFile();
    }
}
