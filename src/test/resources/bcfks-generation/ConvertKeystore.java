
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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class ConvertKeystore {
    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: ConvertKeystore <srcFile> <srcType> <srcPass> <destFile> [destPass]");
            System.exit(1);
        }
        String srcFile = args[0];
        String srcType = args[1];
        String srcPass = args[2];
        String destFile = args[3];
        String destPass = args.length > 4 ? args[4] : srcPass;

        Security.addProvider(new BouncyCastleFipsProvider());

        KeyStore srcKs = KeyStore.getInstance(srcType);
        try (InputStream is = new FileInputStream(srcFile)) {
            srcKs.load(is, srcPass.toCharArray());
        }

        KeyStore destKs = KeyStore.getInstance("BCFKS");
        destKs.load(null, destPass.toCharArray());

        Enumeration<String> aliases = srcKs.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (srcKs.isKeyEntry(alias)) {
                Key key = null;
                for (String kpass : new String[] { srcPass, "" }) {
                    try {
                        key = srcKs.getKey(alias, kpass.toCharArray());
                        if (key != null) break;
                    } catch (UnrecoverableKeyException ignored) {}
                }
                if (key == null) {
                    System.err.println("WARN: could not recover key for alias '" + alias + "' – skipping");
                    continue;
                }
                Certificate[] chain = srcKs.getCertificateChain(alias);
                destKs.setKeyEntry(alias, key, destPass.toCharArray(), chain);
            } else if (srcKs.isCertificateEntry(alias)) {
                destKs.setCertificateEntry(alias, srcKs.getCertificate(alias));
            }
        }

        try (OutputStream os = new FileOutputStream(destFile)) {
            destKs.store(os, destPass.toCharArray());
        }
        System.out.println("OK  " + srcFile + " -> " + destFile);
    }
}
