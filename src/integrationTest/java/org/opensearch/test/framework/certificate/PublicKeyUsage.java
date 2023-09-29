/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.certificate;

import java.util.Objects;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

// CS-SUPPRESS-SINGLE: RegexpSingleline Extension is used to refer to certificate extensions
/**
* The class is associated with certificate extensions related to key usages. These extensions are defined by
* <a href="https://www.rfc-editor.org/rfc/rfc5280.html">RFC 5280</a> and describes allowed usage of public kay which is embedded in
* certificate. The class is related to the following extensions:
* <ol>
*     <li>Key Usage, defined in section <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3">4.2.1.3</a></li>
*     <li>Extended Key Usage, defined in section <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12">4.2.1.12</a></li>
* </ol>
*
* @see <a href="https://www.rfc-editor.org/rfc/rfc5280.html">RFC 5280</a>
*/
// CS-ENFORCE-SINGLE
enum PublicKeyUsage {
    DIGITAL_SIGNATURE(KeyUsage.digitalSignature),
    KEY_CERT_SIGN(KeyUsage.keyCertSign),
    CRL_SIGN(KeyUsage.cRLSign),
    NON_REPUDIATION(KeyUsage.nonRepudiation),
    KEY_ENCIPHERMENT(KeyUsage.keyEncipherment),

    SERVER_AUTH(KeyPurposeId.id_kp_serverAuth),

    CLIENT_AUTH(KeyPurposeId.id_kp_clientAuth);

    private final int keyUsage;
    private final KeyPurposeId id;

    PublicKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
        this.id = null;
    }

    PublicKeyUsage(KeyPurposeId id) {
        this.id = Objects.requireNonNull(id, "Key purpose id is required.");
        this.keyUsage = 0;
    }

    boolean isExtendedUsage() {
        return this.id != null;
    }

    boolean isNotExtendedUsage() {
        return this.id == null;
    }

    int asInt() {
        if (isExtendedUsage()) {
            throw new RuntimeException("Integer value is not available for extended key usage");
        }
        return keyUsage;
    }

    KeyPurposeId getKeyPurposeId() {
        if (isExtendedUsage() == false) {
            throw new RuntimeException("Key purpose id is not available.");
        }
        return id;
    }
}
