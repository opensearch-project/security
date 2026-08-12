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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.opensearch.OpenSearchException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

public class PemKeyReaderLoadKeyStoreTest {

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void returnsNullWhenPathIsNullAndTypeIsNotPkcs11() throws Exception {
        assertNull(PemKeyReader.loadKeyStore(null, null, PemKeyReader.BCFKS));
    }

    @Test
    public void loadsBcfksStore() throws Exception {
        File file = storeFile();
        KeyStore ks = PemKeyReader.loadKeyStore(file.getAbsolutePath(), null, PemKeyReader.BCFKS);
        assertThat(ks, notNullValue());
        assertThat(ks.getType(), equalTo(PemKeyReader.BCFKS));
    }

    @Test
    public void pkcs11ThrowsDescriptiveExceptionWhenProviderUnconfigured() {
        // In a standard test environment there is no PKCS#11 token configured,
        // so getInstance or load will fail — verify our message wraps it.
        OpenSearchException ex = assertThrows(OpenSearchException.class, () -> PemKeyReader.loadKeyStore(null, null, PemKeyReader.PKCS11));
        assertThat(ex.getMessage(), containsString("Failed to initialize PKCS#11 keystore"));
        assertThat(ex.getCause(), notNullValue());
        assertThat(ex.getCause().getMessage(), containsString("PKCS11 not found"));
    }

    private File storeFile() throws Exception {
        File file = tempDir.newFile("store.bcfks");
        KeyStore ks = KeyStore.getInstance("BCFKS");
        ks.load(null, null);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ks.store(fos, new char[0]);
        }
        return file;
    }
}
