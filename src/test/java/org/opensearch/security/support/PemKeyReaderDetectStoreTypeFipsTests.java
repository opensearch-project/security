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

import org.junit.Ignore;
import org.junit.Test;

import static org.hamcrest.Matchers.equalTo;

/**
 * FIPS variant of {@link PemKeyReaderDetectStoreTypeTest}. Pointing the plugin at a JKS or PKCS12
 * store is a reachable operator misconfiguration on a FIPS node, so instead of dropping those
 * cases the variant asserts that {@link PemKeyReader} rejects them. The rejection has to name the
 * store type that was refused *and* the supported alternatives, because that remediation hint is
 * the only actionable part for whoever has to fix the configuration; asserting the whole message
 * keeps it from being silently dropped or reworded into something unhelpful. BCFKS detection and
 * the error paths are inherited unchanged.
 */
public class PemKeyReaderDetectStoreTypeFipsTests extends PemKeyReaderDetectStoreTypeTest {

    @Override
    @Test
    public void detectsJks() throws Exception {
        File file = storeFile("JKS");
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.extractStoreType(file.getAbsolutePath(), null)
        );
        assertThat(ex.getMessage(), equalTo("JKS keystores / truststores are not supported in FIPS mode - use BCFKS or PKCS#11"));
    }

    @Override
    @Test
    @Ignore("A PKCS12 store cannot even be written under FIPS: HmacPBESHA256 is unavailable")
    public void detectsPkcs12() {}

    @Override
    @Test
    public void explicitTypeSkipsDetection() throws Exception {
        // An explicitly declared store type still has to clear the FIPS check; detection is
        // skipped but the rejection is not.
        File file = tempDir.newFile("irrelevant.bin");
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(new byte[] { 0x00, 0x01, 0x02, 0x03 });
        }
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.extractStoreType(file.getAbsolutePath(), PemKeyReader.PKCS12)
        );
        assertThat(ex.getMessage(), equalTo("PKCS12 keystores / truststores are not supported in FIPS mode - use BCFKS or PKCS#11"));
    }
}
