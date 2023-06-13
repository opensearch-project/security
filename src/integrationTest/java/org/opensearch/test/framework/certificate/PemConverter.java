/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
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

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.security.PrivateKey;
import java.security.SecureRandom;

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;

import static java.util.Objects.requireNonNull;

/**
* The class provides a method useful for converting certificate and private key into PEM format
* @see <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
*/
class PemConverter {

    private PemConverter() {}

    private static final Logger log = LogManager.getLogger(PemConverter.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
    * It converts certificate represented by {@link X509CertificateHolder} object to PEM format
    * @param certificate is a certificate to convert
    * @return {@link String} which contains PEM encoded certificate
    */
    public static String toPem(X509CertificateHolder certificate) {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(stringWriter)) {
            writer.writeObject(requireNonNull(certificate, "Certificate is required."));
        } catch (Exception e) {
            throw new RuntimeException("Cannot write certificate in PEM format", e);
        }
        return stringWriter.toString();
    }

    /**
    * It converts private key represented by class {@link PrivateKey} to PEM format.
    * @param privateKey is a private key, cannot be <code>null</code>
    * @param privateKeyPassword is a password used to encode private key, <code>null</code> for unencrypted private key
    * @return {@link String} which contains PEM encoded private key
    */
    public static String toPem(PrivateKey privateKey, String privateKeyPassword) {
        try (StringWriter stringWriter = new StringWriter()) {
            savePrivateKey(stringWriter, requireNonNull(privateKey, "Private key is required."), privateKeyPassword);
            return stringWriter.toString();
        } catch (IOException e) {
            throw new RuntimeException("Cannot convert private key into PEM format.", e);
        }
    }

    private static void savePrivateKey(Writer out, PrivateKey privateKey, String privateKeyPassword) {
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(createPkcs8PrivateKeyPem(privateKey, privateKeyPassword));
        } catch (Exception e) {
            log.error("Error while writing private key.", e);
            throw new RuntimeException("Error while writing private key ", e);
        }
    }

    private static PemObject createPkcs8PrivateKeyPem(PrivateKey privateKey, String password) {
        try {
            OutputEncryptor outputEncryptor = password == null ? null : getPasswordEncryptor(password);
            return new PKCS8Generator(PrivateKeyInfo.getInstance(privateKey.getEncoded()), outputEncryptor).generate();
        } catch (PemGenerationException | OperatorCreationException e) {
            log.error("Creating PKCS8 private key failed", e);
            throw new RuntimeException("Creating PKCS8 private key failed", e);
        }
    }

    private static OutputEncryptor getPasswordEncryptor(String password) throws OperatorCreationException {
        if (!Strings.isNullOrEmpty(password)) {
            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
            encryptorBuilder.setRandom(secureRandom);
            encryptorBuilder.setPassword(password.toCharArray());
            return encryptorBuilder.build();
        }
        return null;
    }
}
