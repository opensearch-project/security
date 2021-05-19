package org.opensearch.security.ssl.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class KeystoreProps {
    private final String filePath;
    private final String type;
    private final char[] password;

    public KeystoreProps(String filePath, String type, String password) {
        this.filePath = filePath;
        this.type = type;
        this.password = Utils.toCharArray(password);
    }

    public String getFilePath() {
        return filePath;
    }

    public String getType() {
        return type;
    }

    public char[] getPassword() {
        return password;
    }

    public KeyStore loadKeystore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore ts = KeyStore.getInstance(type);
        ts.load(new FileInputStream(new File(filePath)), password);
        return ts;
    }
}
