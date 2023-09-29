/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
/*
* Copyright 2021 floragunn GmbH
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

package org.opensearch.test.framework.certificate;

import java.security.Key;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

/**
* The class contains all data related to Certificate including private key which is considered to be a secret.
*/
public class CertificateData {

    private final X509CertificateHolder certificate;
    private final KeyPair keyPair;

    public CertificateData(X509CertificateHolder certificate, KeyPair keyPair) {
        this.certificate = certificate;
        this.keyPair = keyPair;
    }

    /**
    * The method returns X.509 certificate encoded in PEM format. PEM format is defined by
    * <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>.
    * @return Certificate in PEM format
    */
    public String certificateInPemFormat() {
        return PemConverter.toPem(certificate);
    }

    public X509Certificate certificate() {
        try {
            return new JcaX509CertificateConverter().getCertificate(certificate);
        } catch (CertificateException e) {
            throw new RuntimeException("Cannot retrieve certificate", e);
        }
    }

    /**
    * It returns the private key associated with certificate encoded in PEM format. PEM format is defined by
    * <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>.
    * @param privateKeyPassword password used for private key encryption. <code>null</code> for unencrypted key.
    * @return private key encoded in PEM format
    */
    public String privateKeyInPemFormat(String privateKeyPassword) {
        return PemConverter.toPem(keyPair.getPrivate(), privateKeyPassword);
    }

    X500Name getCertificateSubject() {
        return certificate.getSubject();
    }

    KeyPair getKeyPair() {
        return keyPair;
    }

    public Key getKey() {
        return keyPair.getPrivate();
    }
}
