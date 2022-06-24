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

package org.opensearch.security.ssl.util;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.file.FileHelper;

public class CertFromTruststoreTests {

    @Test
    public void testLoadSameCertForClientServerUsage() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeystoreProps props = new KeystoreProps(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/truststore.jks").toString(),
            "JKS",
            "changeit"
        );

        CertFromTruststore cert = new CertFromTruststore(props, "root-ca");

        Assert.assertEquals(1, cert.getClientTrustedCerts().length);
        Assert.assertTrue(cert.getClientTrustedCerts().equals(cert.getServerTrustedCerts()));
    }

    @Test
    public void testLoadSameCertWithoutAlias() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeystoreProps props = new KeystoreProps(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/truststore.jks").toString(),
            "JKS",
            "changeit"
        );

        CertFromTruststore cert = new CertFromTruststore(props, null);

        Assert.assertEquals(1, cert.getClientTrustedCerts().length);
    }

    public void testLoadDifferentCertsForClientServerUsage() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeystoreProps props = new KeystoreProps(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/truststore.jks").toString(),
            "JKS",
            "changeit"
        );

        CertFromTruststore cert = new CertFromTruststore(props, "root-ca", "root-ca");

        Assert.assertEquals(1, cert.getClientTrustedCerts().length);
        Assert.assertEquals(1, cert.getServerTrustedCerts().length);
        // we are loading same cert twice
        Assert.assertFalse(cert.getClientTrustedCerts().equals(cert.getServerTrustedCerts()));
    }
}
