package com.amazon.opendistroforelasticsearch.security.ssl.util;


public class CertFileProps {
  private final String pemCertFilePath;
  private final String pemKeyFilePath;
  private final String trustedCasFilePath;
  private final String pemKeyPassword;

  public CertFileProps(String pemCertFilePath, String pemKeyFilePath, String trustedCasFilePath, String pemKeyPassword) {
    this.pemCertFilePath = pemCertFilePath;
    this.pemKeyFilePath = pemKeyFilePath;
    this.trustedCasFilePath = trustedCasFilePath;
    this.pemKeyPassword = pemKeyPassword;
  }

  public String getPemCertFilePath() {
    return pemCertFilePath;
  }

  public String getPemKeyFilePath() {
    return pemKeyFilePath;
  }

  public String getTrustedCasFilePath() {
    return trustedCasFilePath;
  }

  public String getPemKeyPassword() {
    return pemKeyPassword;
  }
}
