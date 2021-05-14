package org.opensearch.security.ssl.util;

import java.io.FileNotFoundException;

import org.opensearch.security.test.helper.file.FileHelper;

import org.junit.Assert;
import org.junit.Test;

public class CertFromFileTests {

    @Test
    public void testLoadSameCertForClientServerUsage() throws Exception {
      CertFileProps certProps = new CertFileProps(
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem").toString(),
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem").toString(),
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem").toString(),
          null);

      CertFromFile cert = new CertFromFile(certProps);

      Assert.assertEquals(1, cert.getCerts().length);
      Assert.assertNotNull(cert.getClientPemCert());
      Assert.assertNotNull(cert.getClientPemKey());
      Assert.assertNotNull(cert.getClientTrustedCas());
    }

  @Test
  public void testLoadCertWithoutCA() throws Exception {
        CertFileProps certProps = new CertFileProps(
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem").toString(),
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem").toString(),
            null,
            null);

        CertFromFile cert = new CertFromFile(certProps);

        Assert.assertNull(cert.getClientTrustedCas());
    }

    @Test(expected= FileNotFoundException.class)
    public void testLoadCertWithMissingFiles() throws Exception {
        CertFileProps certProps = new CertFileProps(
            "missing.pem",
            FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem").toString(),
            null,
            null);

        CertFromFile cert = new CertFromFile(certProps);
    }

    @Test
    public void testLoadDifferentCertsForClientServerUsage() throws Exception {
      CertFileProps clientCertProps = new CertFileProps(
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-client.pem").toString(),
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-key-client.pem").toString(),
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/root-ca.pem").toString(),
          null);
      CertFileProps servertCertProps = new CertFileProps(
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-server.pem").toString(),
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-key-server.pem").toString(),
          FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/root-ca.pem").toString(),
          null);

      CertFromFile cert = new CertFromFile(clientCertProps, servertCertProps);

      Assert.assertEquals(2, cert.getCerts().length);
    }

}
