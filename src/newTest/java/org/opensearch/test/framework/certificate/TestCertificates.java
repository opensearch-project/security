/*
 * Copyright 2021 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.test.framework.certificate;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Provides TLS certificates required in test cases.
 * WIP At the moment the certificates are hard coded. 
 * This will be replaced by classes
 * that can generate certificates on the fly.
 */
public class TestCertificates {

    public File getRootCertificate() throws IOException {
    	return createTempFile("root", ".cert", Certificates.ROOT_CA_CERTIFICATE);
    }

    public File getNodeCertificate(int node) throws IOException {
    	return createTempFile("node-" + node, ".cert", Certificates.NODE_CERTIFICATE);
    }

    public File getNodeKey(int node) throws IOException {
    	return createTempFile("node-" + node, ".key", Certificates.NODE_KEY);
    }

    public File getAdminCertificate() throws IOException {
    	return createTempFile("admin", ".cert", Certificates.ADMIN_CERTIFICATE);
    }

    public File getAdminKey() throws IOException {
    	return createTempFile("admin", ".key", Certificates.ADMIN_KEY);
    }

    public String[] getAdminDNs() throws IOException {
    	return new String[] {"CN=kirk,OU=client,O=client,L=test,C=de"};
    }

    private File createTempFile(String name, String suffix, String contents) throws IOException {
    	Path path = Files.createTempFile(name, suffix);
    	Files.writeString(path, contents);
    	return path.toFile();
    	
    }
}
