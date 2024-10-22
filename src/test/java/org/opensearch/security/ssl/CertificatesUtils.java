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

package org.opensearch.security.ssl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;

public class CertificatesUtils {

    public static void writePemContent(final Path path, final Object pemContent) throws IOException {
        try (JcaPEMWriter writer = new JcaPEMWriter(Files.newBufferedWriter(path))) {
            writer.writeObject(pemContent);
        }
    }

    public static PemObject privateKeyToPemObject(final PrivateKey privateKey, final String password) throws Exception {
        return new PKCS8Generator(
            PrivateKeyInfo.getInstance(privateKey.getEncoded()),
            new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES).setRandom(new SecureRandom())
                .setPassword(password.toCharArray())
                .build()
        ).generate();
    }

}
