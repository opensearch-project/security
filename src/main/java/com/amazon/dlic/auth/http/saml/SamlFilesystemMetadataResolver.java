/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.saml;

import java.io.File;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;

import net.shibboleth.utilities.java.support.resolver.ResolverException;

public class SamlFilesystemMetadataResolver extends FilesystemMetadataResolver {

    SamlFilesystemMetadataResolver(String filePath, Settings esSettings, Path configPath) throws Exception {
        super(getMetadataFile(filePath, esSettings, configPath));
    }

    @Override
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
