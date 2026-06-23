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

package org.opensearch.security.ssl.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

public class SanParser {

    private static final Logger LOGGER = LogManager.getLogger(SanParser.class);

    private SanParser() {}

    public static String parse(X509Certificate certificate) {
        try {
            X509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
            GeneralNames generalNames = GeneralNames.fromExtensions(holder.getExtensions(), Extension.subjectAlternativeName);
            if (generalNames == null) return "";

            Comparator<List<?>> comparator = Comparator.comparing((List<?> n) -> (Integer) n.get(0))
                .thenComparing((List<?> n) -> n.get(1).toString());
            Set<List<?>> sans = new TreeSet<>(comparator);

            for (GeneralName gn : generalNames.getNames()) {
                int type = gn.getTagNo();
                if (type == GeneralName.otherName) {
                    OtherName on = OtherName.getInstance(gn.getName());
                    ASN1Encodable value = on.getValue();
                    if (value instanceof ASN1String) {
                        sans.add(List.of(type, List.of(on.getTypeID().getId(), value.toString())));
                    } else {
                        LOGGER.warn("Couldn't parse OtherName SAN value");
                    }
                } else if (type == GeneralName.iPAddress) {
                    byte[] octets = ASN1OctetString.getInstance(gn.getName()).getOctets();
                    sans.add(List.of(type, InetAddress.getByAddress(octets).getHostAddress()));
                } else {
                    sans.add(List.of(type, gn.getName().toString()));
                }
            }
            return sans.isEmpty() ? "" : sans.toString();
        } catch (final CertificateEncodingException | UnknownHostException e) {
            LOGGER.error("Couldn't parse subject alternative names", e);
            if (CryptoServicesRegistrar.isInApprovedOnlyMode()) {
                throw new RuntimeException("Couldn't parse subject alternative names", e);
            }
            return "";
        }
    }
}
