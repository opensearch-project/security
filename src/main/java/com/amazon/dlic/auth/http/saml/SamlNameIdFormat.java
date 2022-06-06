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

package com.amazon.dlic.auth.http.saml;

import java.util.HashMap;
import java.util.Map;

public class SamlNameIdFormat {
    private static Map<String, SamlNameIdFormat> KNOWN_NAME_ID_FORMATS_BY_URI = new HashMap<>();
    private static Map<String, SamlNameIdFormat> KNOWN_NAME_ID_FORMATS_BY_SHORT_NAME = new HashMap<>();

    static {
        add("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", "u");
        add("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "email");
        add("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName", "sn");
        add("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos", "ker");
        add("urn:oasis:names:tc:SAML:2.0:nameid-format:entity", "ent");
        add("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "p");
        add("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "t");
    }

    private final String uri;
    private final String shortName;

    SamlNameIdFormat(String uri, String shortName) {
        this.uri = uri;
        this.shortName = shortName;
    }

    public String getUri() {
        return uri;
    }

    public String getShortName() {
        return shortName;
    }

    static SamlNameIdFormat getByUri(String uri) {
        SamlNameIdFormat samlNameIdFormat = KNOWN_NAME_ID_FORMATS_BY_URI.get(uri);

        if (samlNameIdFormat == null) {
            samlNameIdFormat = new SamlNameIdFormat(uri, uri);
        }

        return samlNameIdFormat;
    }

    static SamlNameIdFormat getByShortName(String shortNameOrUri) {
        SamlNameIdFormat samlNameIdFormat = KNOWN_NAME_ID_FORMATS_BY_SHORT_NAME.get(shortNameOrUri);

        if (samlNameIdFormat == null) {
            samlNameIdFormat = new SamlNameIdFormat(shortNameOrUri, shortNameOrUri);
        }

        return samlNameIdFormat;
    }

    private static void add(String uri, String shortName) {
        SamlNameIdFormat samlNameIdFormat = new SamlNameIdFormat(uri, shortName);
        KNOWN_NAME_ID_FORMATS_BY_URI.put(uri, samlNameIdFormat);
        KNOWN_NAME_ID_FORMATS_BY_SHORT_NAME.put(shortName, samlNameIdFormat);
    }

}
