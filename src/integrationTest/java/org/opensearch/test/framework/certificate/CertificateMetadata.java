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

// CS-SUPPRESS-SINGLE: RegexpSingleline Extension is used to refer to certificate extensions, keeping this rule disable for the whole file
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import com.google.common.base.Strings;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.Objects.requireNonNull;

/**
* <p>
* The class represents metadata which should be embedded in certificate to describe a certificate subject (person, company, web server,
* IoT device). The class contains some basic metadata and metadata which should be placed in certificate extensions.
* </p>
*
* <p>
*     The class is immutable.
* </p>
*
*/
class CertificateMetadata {
    /**
    * Certification subject (person, company, web server, IoT device). The subject of certificate is an owner of the certificate
    * (simplification). The format of this field must adhere to RFC 4514.
    * @see <a href="https://www.baeldung.com/javadoc-linking-external-url">RFC 4514</a>
    */
    private final String subject;

    /**
    * It describes certificate expiration date
    */
    private final int validityDays;

    /**
    * Optionally used by Open Search to indicate that the certificate can be used by Open Search node to confirm the node identity. The
    * value becomes a part of
    * <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6">SAN (Subject Alternative Name) extension</a>
    *
    * @see #dnsNames
    * @see <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6">SAN (Subject Alternative Name) extension</a>
    */
    private final String nodeOid;

    /**
    * The certificate contains only one {@link #subject}. This is a common limitation when a certificate is used by a web server which is
    * associated with a few domains. To overcome this limitation SAN (Subject Alternative Name) extension was introduced.
    * The field contains additional subject names which enables creation of so called multi-domain certificates. The extension is defined
    * in section <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6">4.2.1.6 of RFC 5280</a>
    *
    * @see <a href="https://www.rfc-editor.org/rfc/rfc5280.html">RFC 5280</a>
    */
    private final List<String> dnsNames;

    /**
    * Similar to {@link #dnsNames} but contains IP addresses instead of domains.
    */
    private final List<String> ipAddresses;

    /**
    * If a private key associated with certificate is used to sign other certificate then this field has to be <code>true</code>.
    */
    private final boolean basicConstrainIsCa;

    /**
    * Allowed usages for public key associated with certificate
    */
    private final Set<PublicKeyUsage> keyUsages;

    private CertificateMetadata(
        String subject,
        int validityDays,
        String nodeOid,
        List<String> dnsNames,
        List<String> ipAddresses,
        boolean basicConstrainIsCa,
        Set<PublicKeyUsage> keyUsages
    ) {
        this.subject = subject;
        this.validityDays = validityDays;
        this.nodeOid = nodeOid;
        this.dnsNames = requireNonNull(dnsNames, "List of dns names must not be null.");
        this.ipAddresses = requireNonNull(ipAddresses, "List of IP addresses must not be null");
        this.basicConstrainIsCa = basicConstrainIsCa;
        this.keyUsages = requireNonNull(keyUsages, "Key usage set must not be null.");
    }

    /**
    * Static factory method. It creates metadata which contains only basic information.
    * @param subjectName please see {@link #subject}
    * @param validityDays please see {@link #validityDays}
    * @return new instance of {@link CertificateMetadata}
    */
    public static CertificateMetadata basicMetadata(String subjectName, int validityDays) {
        return new CertificateMetadata(subjectName, validityDays, null, emptyList(), emptyList(), false, emptySet());
    }

    /**
    * It is related to private key associated with certificate. It specifies metadata related to allowed private key usage.
    * @param basicConstrainIsCa {@link #basicConstrainIsCa}
    * @param keyUsages {@link #keyUsages}
    * @return returns newly created instance of {@link CertificateData}
    */
    public CertificateMetadata withKeyUsage(boolean basicConstrainIsCa, PublicKeyUsage... keyUsages) {
        Set<PublicKeyUsage> usages = arrayToEnumSet(keyUsages);
        return new CertificateMetadata(subject, validityDays, nodeOid, dnsNames, ipAddresses, basicConstrainIsCa, usages);
    }

    private <T extends Enum<T>> Set<T> arrayToEnumSet(T[] enumArray) {
        if ((enumArray == null) || (enumArray.length == 0)) {
            return Collections.emptySet();
        }
        return EnumSet.copyOf(asList(enumArray));
    }

    /**
    * The method defines metadata related to SAN (Subject Alternative Name) extension.
    * @param nodeOid {@link #nodeOid}
    * @param dnsNames {@link #dnsNames}
    * @param ipAddresses {@link #ipAddresses}
    * @return new instance of {@link CertificateMetadata}
    * @see <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6">SAN (Subject Alternative Name) extension</a>
    */
    public CertificateMetadata withSubjectAlternativeName(String nodeOid, List<String> dnsNames, String... ipAddresses) {
        return new CertificateMetadata(subject, validityDays, nodeOid, dnsNames, asList(ipAddresses), basicConstrainIsCa, keyUsages);
    }

    /**
    * {@link #subject}
    * @return Subject name
    */
    public String getSubject() {
        return subject;
    }

    /**
    * {@link #validityDays}
    * @return determines certificate expiration date
    */
    public int getValidityDays() {
        return validityDays;
    }

    /**
    * {@link #basicConstrainIsCa}
    * @return Determines if another certificate can be derived from certificate.
    */
    public boolean isBasicConstrainIsCa() {
        return basicConstrainIsCa;
    }

    KeyUsage asKeyUsage() {
        Integer keyUsageBitMask = keyUsages.stream()
            .filter(PublicKeyUsage::isNotExtendedUsage)
            .map(PublicKeyUsage::asInt)
            .reduce(0, (accumulator, currentValue) -> accumulator | currentValue);
        return new KeyUsage(keyUsageBitMask);
    }

    boolean hasSubjectAlternativeNameExtension() {
        return ((ipAddresses.size() + dnsNames.size()) > 0) || (Strings.isNullOrEmpty(nodeOid) == false);
    }

    DERSequence createSubjectAlternativeNames() {
        List<ASN1Encodable> subjectAlternativeNameList = new ArrayList<>();
        if (!Strings.isNullOrEmpty(nodeOid)) {
            subjectAlternativeNameList.add(new GeneralName(GeneralName.registeredID, nodeOid));
        }
        if (isNotEmpty(dnsNames)) {
            for (String dnsName : dnsNames) {
                subjectAlternativeNameList.add(new GeneralName(GeneralName.dNSName, dnsName));
            }
        }
        if (isNotEmpty(ipAddresses)) {
            for (String ip : ipAddresses) {
                subjectAlternativeNameList.add(new GeneralName(GeneralName.iPAddress, ip));
            }
        }
        return new DERSequence(subjectAlternativeNameList.toArray(ASN1Encodable[]::new));
    }

    private static <T> boolean isNotEmpty(Collection<T> collection) {
        return (collection != null) && (!collection.isEmpty());
    }

    boolean hasExtendedKeyUsage() {
        return keyUsages.stream().anyMatch(PublicKeyUsage::isNotExtendedUsage);
    }

    ExtendedKeyUsage getExtendedKeyUsage() {
        KeyPurposeId[] usages = keyUsages.stream()
            .filter(PublicKeyUsage::isExtendedUsage)
            .map(PublicKeyUsage::getKeyPurposeId)
            .toArray(KeyPurposeId[]::new);
        return new ExtendedKeyUsage(usages);
    }
}
// CS-ENFORCE-SINGLE
