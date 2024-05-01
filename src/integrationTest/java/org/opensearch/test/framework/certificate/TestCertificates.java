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

package org.opensearch.test.framework.certificate;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static org.opensearch.test.framework.certificate.PublicKeyUsage.CLIENT_AUTH;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.CRL_SIGN;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.DIGITAL_SIGNATURE;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.KEY_CERT_SIGN;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.KEY_ENCIPHERMENT;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.NON_REPUDIATION;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.SERVER_AUTH;

/**
* It provides TLS certificates required in test cases. The certificates are generated during process of creation objects of the class.
* The class exposes method which can be used to write certificates and private keys in temporally files.
*/
public class TestCertificates {

    private static final Logger log = LogManager.getLogger(TestCertificates.class);

    public static final Integer DEFAULT_NUMBER_OF_NODE_CERTIFICATES = 3;

    public static final String CA_SUBJECT = "DC=com,DC=example,O=Example Com Inc.,OU=Example Com Inc. Root CA,CN=Example Com Inc. Root CA";

    public static final String LDAP_SUBJECT = "DC=de,L=test,O=node,OU=node,CN=ldap.example.com";
    public static final String NODE_SUBJECT_PATTERN = "DC=de,L=test,O=node,OU=node,CN=node-%d.example.com";

    private static final String ADMIN_DN = "CN=kirk,OU=client,O=client,L=test,C=de";
    private static final int CERTIFICATE_VALIDITY_DAYS = 365;
    private static final String CERTIFICATE_FILE_EXT = ".cert";
    private static final String KEY_FILE_EXT = ".key";
    private final CertificateData caCertificate;
    private final CertificateData adminCertificate;
    private final List<CertificateData> nodeCertificates;

    private final int numberOfNodes;

    private final CertificateData ldapCertificate;

    public TestCertificates() {
        this(DEFAULT_NUMBER_OF_NODE_CERTIFICATES);
    }

    public TestCertificates(final int numberOfNodes) {
        this.caCertificate = createCaCertificate();
        this.numberOfNodes = numberOfNodes;
        this.nodeCertificates = IntStream.range(0, this.numberOfNodes).mapToObj(this::createNodeCertificate).collect(Collectors.toList());
        this.ldapCertificate = createLdapCertificate();
        this.adminCertificate = createAdminCertificate(ADMIN_DN);
        log.info("Test certificates successfully generated");
    }

    private CertificateData createCaCertificate() {
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(CA_SUBJECT, CERTIFICATE_VALIDITY_DAYS)
            .withKeyUsage(true, DIGITAL_SIGNATURE, KEY_CERT_SIGN, CRL_SIGN);
        return CertificatesIssuerFactory.rsaBaseCertificateIssuer().issueSelfSignedCertificate(metadata);
    }

    public CertificateData createAdminCertificate(String adminDn) {
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(adminDn, CERTIFICATE_VALIDITY_DAYS)
            .withKeyUsage(false, DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, CLIENT_AUTH);
        return CertificatesIssuerFactory.rsaBaseCertificateIssuer().issueSignedCertificate(metadata, caCertificate);
    }

    public CertificateData createSelfSignedCertificate(String distinguishedName) {
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(distinguishedName, CERTIFICATE_VALIDITY_DAYS);
        return CertificatesIssuerFactory.rsaBaseCertificateIssuer().issueSelfSignedCertificate(metadata);
    }

    /**
    * It returns the most trusted certificate. Certificates for nodes and users are derived from this certificate.
    * @return file which contains certificate in PEM format, defined by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
    */
    public File getRootCertificate() {
        return createTempFile("root", CERTIFICATE_FILE_EXT, caCertificate.certificateInPemFormat());
    }

    public CertificateData getRootCertificateData() {
        return caCertificate;
    }

    /**
    * Certificate for Open Search node. The certificate is derived from root certificate, returned by method {@link #getRootCertificate()}
    * @param node is a node index. It has to be less than {@link #DEFAULT_NUMBER_OF_NODE_CERTIFICATES}
    * @return file which contains certificate in PEM format, defined by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
    */
    public File getNodeCertificate(int node) {
        CertificateData certificateData = getNodeCertificateData(node);
        return createTempFile("node-" + node, CERTIFICATE_FILE_EXT, certificateData.certificateInPemFormat());
    }

    public CertificateData getNodeCertificateData(int node) {
        isCorrectNodeNumber(node);
        return nodeCertificates.get(node);
    }

    private void isCorrectNodeNumber(int node) {
        if (node >= numberOfNodes) {
            String message = String.format(
                "Cannot get certificate for node %d, number of created certificates for nodes is %d",
                node,
                numberOfNodes
            );
            throw new RuntimeException(message);
        }
    }

    private CertificateData createNodeCertificate(Integer node) {
        final var subject = String.format(NODE_SUBJECT_PATTERN, node);
        String domain = String.format("node-%d.example.com", node);
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(subject, CERTIFICATE_VALIDITY_DAYS)
            .withKeyUsage(false, DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, CLIENT_AUTH, SERVER_AUTH)
            .withSubjectAlternativeName("1.2.3.4.5.5", List.of(domain, "localhost"), "127.0.0.1");
        return CertificatesIssuerFactory.rsaBaseCertificateIssuer().issueSignedCertificate(metadata, caCertificate);
    }

    public CertificateData issueUserCertificate(String organizationUnit, String username) {
        String subject = String.format("DC=de,L=test,O=users,OU=%s,CN=%s", organizationUnit, username);
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(subject, CERTIFICATE_VALIDITY_DAYS)
            .withKeyUsage(false, DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, CLIENT_AUTH, SERVER_AUTH);
        return CertificatesIssuerFactory.rsaBaseCertificateIssuer().issueSignedCertificate(metadata, caCertificate);
    }

    private CertificateData createLdapCertificate() {
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(LDAP_SUBJECT, CERTIFICATE_VALIDITY_DAYS)
            .withKeyUsage(false, DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, CLIENT_AUTH, SERVER_AUTH)
            .withSubjectAlternativeName(null, List.of("localhost"), "127.0.0.1");
        return CertificatesIssuerFactory.rsaBaseCertificateIssuer().issueSignedCertificate(metadata, caCertificate);
    }

    public CertificateData getLdapCertificateData() {
        return ldapCertificate;
    }

    /**
    * It returns private key associated with node certificate returned by method {@link #getNodeCertificate(int)}
    *
    * @param node is a node index. It has to be less than {@link #DEFAULT_NUMBER_OF_NODE_CERTIFICATES}
    * @param privateKeyPassword is a password used to encode private key, can be <code>null</code> to retrieve unencrypted key.
    * @return file which contains private key encoded in PEM format, defined
    * by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
    */
    public File getNodeKey(int node, String privateKeyPassword) {
        CertificateData certificateData = nodeCertificates.get(node);
        return createTempFile("node-" + node, KEY_FILE_EXT, certificateData.privateKeyInPemFormat(privateKeyPassword));
    }

    /**
    * Certificate which proofs admin user identity. Certificate is derived from root certificate returned by
    * method {@link #getRootCertificate()}
    * @return file which contains certificate in PEM format, defined by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
    */
    public File getAdminCertificate() {
        return createTempFile("admin", CERTIFICATE_FILE_EXT, adminCertificate.certificateInPemFormat());
    }

    public CertificateData getAdminCertificateData() {
        return adminCertificate;
    }

    /**
    * It returns private key associated with admin certificate returned by {@link #getAdminCertificate()}.
    *
    * @param privateKeyPassword is a password used to encode private key, can be <code>null</code> to retrieve unencrypted key.
    * @return file which contains private key encoded in PEM format, defined
    * by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
    */
    public File getAdminKey(String privateKeyPassword) {
        return createTempFile("admin", KEY_FILE_EXT, adminCertificate.privateKeyInPemFormat(privateKeyPassword));
    }

    public String[] getAdminDNs() {
        return new String[] { ADMIN_DN };
    }

    private File createTempFile(String name, String suffix, String contents) {
        try {
            Path path = Files.createTempFile(name, suffix);
            Files.writeString(path, contents);
            return path.toFile();
        } catch (IOException ex) {
            throw new RuntimeException("Cannot create temp file with name " + name + " and suffix " + suffix);
        }
    }
}
