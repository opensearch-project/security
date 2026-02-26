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

package org.opensearch.security.support;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

public class PemKeyReaderDetectStoreTypeTest {

    static {
        if (Security.getProvider("BCFIPS") == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
    }

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void detectsJks() throws Exception {
        assumeFalse("JKS truststores are not supported in FIPS mode", CryptoServicesRegistrar.isInApprovedOnlyMode());
        File file = storeFile("JKS");
        assertThat(PemKeyReader.extractStoreType(file.getAbsolutePath(), null), equalTo(PemKeyReader.JKS));
    }

    @Test
    public void detectsPkcs12() throws Exception {
        assumeFalse("PKCS12 truststores are not supported in FIPS mode", CryptoServicesRegistrar.isInApprovedOnlyMode());
        File file = storeFile("PKCS12");
        assertThat(PemKeyReader.extractStoreType(file.getAbsolutePath(), null), equalTo(PemKeyReader.PKCS12));
    }

    @Test
    public void detectsBcfks() throws Exception {
        File file = storeFile("BCFKS");
        assertThat(PemKeyReader.extractStoreType(file.getAbsolutePath(), null), equalTo(PemKeyReader.BCFKS));
    }

    @Test
    public void explicitTypeSkipsDetection() throws Exception {
        // file content is irrelevant when type is explicitly provided
        assumeFalse("PKCS12 truststores are not supported in FIPS mode", CryptoServicesRegistrar.isInApprovedOnlyMode());
        File file = tempDir.newFile("irrelevant.bin");
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(new byte[] { 0x00, 0x01, 0x02, 0x03 });
        }
        assertThat(PemKeyReader.extractStoreType(file.getAbsolutePath(), PemKeyReader.PKCS12), equalTo(PemKeyReader.PKCS12));
    }

    @Test
    public void throwsForFileTooShort() throws Exception {
        File file = tempDir.newFile("short.bin");
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(new byte[] { 0x30, 0x00 });
        }
        assertThrows(IllegalArgumentException.class, () -> PemKeyReader.extractStoreType(file.getAbsolutePath(), null));
    }

    @Test
    public void throwsForUnknownFormat() throws Exception {
        File file = tempDir.newFile("unknown.bin");
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 });
        }
        assertThrows(IllegalArgumentException.class, () -> PemKeyReader.extractStoreType(file.getAbsolutePath(), null));
    }

    @Test
    public void throwsForEmptyFile() throws Exception {
        File file = tempDir.newFile("empty.bin");
        assertThrows(IllegalArgumentException.class, () -> PemKeyReader.extractStoreType(file.getAbsolutePath(), null));
    }

    private File storeFile(String type) throws Exception {
        File file = tempDir.newFile("store." + type.toLowerCase());
        KeyStore ks = KeyStore.getInstance(type);
        ks.load(null, null);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ks.store(fos, new char[0]);
        }
        return file;
    }
}
