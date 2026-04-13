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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class CertFromKeystoreTests {

    @Test
    public void testLoadSameCertForClientServerUsage() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException,
        KeyStoreException, IOException {
        var ks0 = FileHelper.resolveStore("ssl/node-0-keystore");
        KeystoreProps props = new KeystoreProps(ks0.path().toString(), ks0.type(), "changeit");

        CertFromKeystore cert = new CertFromKeystore(props, "node-0", "changeit");

        // second cert is Signing cert
        assertThat(cert.getCerts().length, is(2));
        Assert.assertTrue(cert.getCerts()[0].getSubjectDN().getName().contains("node-0"));

        Assert.assertNotNull(cert.getServerKey());
        Assert.assertNotNull(cert.getClientKey());
    }

    @Test
    public void testLoadSameCertWithoutAlias() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException,
        KeyStoreException, IOException {
        var ks1 = FileHelper.resolveStore("ssl/node-0-keystore");
        KeystoreProps props = new KeystoreProps(ks1.path().toString(), ks1.type(), "changeit");

        CertFromKeystore cert = new CertFromKeystore(props, null, "changeit");

        // second cert is Signing cert
        assertThat(cert.getCerts().length, is(2));
        Assert.assertTrue(cert.getCerts()[0].getSubjectDN().getName().contains("node-0"));
    }

    @Test
    public void testLoadDifferentCertsForClientServerUsage() throws UnrecoverableKeyException, CertificateException,
        NoSuchAlgorithmException, KeyStoreException, IOException {
        var ks2 = FileHelper.resolveStore("ssl/extended_key_usage/node-0-keystore");
        KeystoreProps props = new KeystoreProps(ks2.path().toString(), ks2.type(), "changeit");

        CertFromKeystore cert = new CertFromKeystore(props, "node-0-server", "node-0-client", "changeit", "changeit");

        assertThat(cert.getCerts().length, is(4));

        Assert.assertTrue(cert.getClientCert()[0].getSubjectDN().getName().contains("node-client"));
        Assert.assertTrue(cert.getServerCert()[0].getSubjectDN().getName().contains("node-server"));
        Assert.assertNotNull(cert.getServerKey());
        Assert.assertNotNull(cert.getClientKey());
    }
}
