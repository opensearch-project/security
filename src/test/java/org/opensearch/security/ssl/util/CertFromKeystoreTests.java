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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.file.FileHelper;

public class CertFromKeystoreTests {

    @Test
    public void testLoadSameCertForClientServerUsage() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException,
        KeyStoreException, IOException {
        KeystoreProps props = new KeystoreProps(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks").toString(),
            "JKS",
            "changeit"
        );

        CertFromKeystore cert = new CertFromKeystore(props, "node-0", "changeit");

        // second cert is Signing cert
        Assert.assertEquals(2, cert.getCerts().length);
        Assert.assertTrue(cert.getCerts()[0].getSubjectDN().getName().contains("node-0"));

        Assert.assertNotNull(cert.getServerKey());
        Assert.assertNotNull(cert.getClientKey());
    }

    @Test
    public void testLoadSameCertWithoutAlias() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException,
        KeyStoreException, IOException {
        KeystoreProps props = new KeystoreProps(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks").toString(),
            "JKS",
            "changeit"
        );

        CertFromKeystore cert = new CertFromKeystore(props, null, "changeit");

        // second cert is Signing cert
        Assert.assertEquals(2, cert.getCerts().length);
        Assert.assertTrue(cert.getCerts()[0].getSubjectDN().getName().contains("node-0"));
    }

    @Test
    public void testLoadDifferentCertsForClientServerUsage() throws UnrecoverableKeyException, CertificateException,
        NoSuchAlgorithmException, KeyStoreException, IOException {
        KeystoreProps props = new KeystoreProps(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-0-keystore.jks").toString(),
            "JKS",
            "changeit"
        );

        CertFromKeystore cert = new CertFromKeystore(props, "node-0-server", "node-0-client", "changeit", "changeit");

        Assert.assertEquals(4, cert.getCerts().length);

        Assert.assertTrue(cert.getClientCert()[0].getSubjectDN().getName().contains("node-client"));
        Assert.assertTrue(cert.getServerCert()[0].getSubjectDN().getName().contains("node-server"));
        Assert.assertNotNull(cert.getServerKey());
        Assert.assertNotNull(cert.getClientKey());
    }
}
