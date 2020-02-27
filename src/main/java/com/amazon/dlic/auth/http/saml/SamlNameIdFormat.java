/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
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
