package com.amazon.opendistroforelasticsearch.security.ssl.util;

import com.amazon.opendistroforelasticsearch.security.support.PemKeyReader;

import java.io.File;
import java.security.cert.X509Certificate;

public class CertFromFile {
    private final CertFileProps clientCertProps;
    private final CertFileProps serverCertProps;

    private final File serverPemCert;
    private final File serverPemKey;
    private final File serverTrustedCas;

    private final File clientPemCert;
    private final File clientPemKey;
    private final File clientTrustedCas;

    private final X509Certificate[] loadedCerts;

    public CertFromFile(CertFileProps clientCertProps, CertFileProps serverCertProps) throws Exception {
        this.serverCertProps = serverCertProps;
        this.serverPemCert = new File(serverCertProps.getPemCertFilePath());
        this.serverPemKey = new File(serverCertProps.getPemKeyFilePath());
        this.serverTrustedCas = nullOrFile(serverCertProps.getTrustedCasFilePath());

        this.clientCertProps = clientCertProps;
        this.clientPemCert = new File(clientCertProps.getPemCertFilePath());
        this.clientPemKey = new File(clientCertProps.getPemKeyFilePath());
        this.clientTrustedCas = nullOrFile(clientCertProps.getTrustedCasFilePath());

        loadedCerts = new X509Certificate[]{PemKeyReader.loadCertificateFromFile(clientCertProps.getPemCertFilePath()),
                PemKeyReader.loadCertificateFromFile(serverCertProps.getPemCertFilePath())};
    }

    public CertFromFile(CertFileProps certProps) throws Exception {
        this.serverCertProps = certProps;
        this.serverPemCert = new File(certProps.getPemCertFilePath());
        this.serverPemKey = new File(certProps.getPemKeyFilePath());
        this.serverTrustedCas = nullOrFile(certProps.getTrustedCasFilePath());

        this.clientCertProps = serverCertProps;
        this.clientPemCert = serverPemCert;
        this.clientPemKey = serverPemKey;
        this.clientTrustedCas = serverTrustedCas;

        loadedCerts = new X509Certificate[]{PemKeyReader.loadCertificateFromFile(certProps.getPemCertFilePath())};
    }

    public X509Certificate[] getCerts() {
        return loadedCerts;
    }

    public File getServerPemKey() {
        return serverPemKey;
    }

    public File getServerPemCert() {
        return serverPemCert;
    }

    public File getServerTrustedCas() {
        return serverTrustedCas;
    }

    public String getServerPemKeyPassword() {
        return serverCertProps.getPemKeyPassword();
    }

    public File getClientPemKey() {
        return clientPemKey;
    }

    public File getClientPemCert() {
        return clientPemCert;
    }

    public File getClientTrustedCas() {
        return clientTrustedCas;
    }

    public String getClientPemKeyPassword() {
        return clientCertProps.getPemKeyPassword();
    }

    private File nullOrFile(String path) {
        if (path != null) {
            return new File(path);
        }
        return null;
    }
}
