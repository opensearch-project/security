/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.ldap;

import org.apache.commons.lang3.StringUtils;

/**
* Value object which represents LDIF file data and some metadata. Ensure type safety.
*/
public class LdifData {

    private final String rootDistinguishedName;

    private final String content;

    LdifData(String rootDistinguishedName, String content) {
        this.rootDistinguishedName = requireNotBlank(rootDistinguishedName, "Root distinguished name is required");
        this.content = requireNotBlank(content, "Ldif file content is required");

    }

    private static String requireNotBlank(String string, String message) {
        if (StringUtils.isBlank(string)) {
            throw new IllegalArgumentException(message);
        }
        return string;
    }

    String getContent() {
        return content;
    }

    String getRootDistinguishedName() {
        return rootDistinguishedName;
    }

    @Override
    public String toString() {
        return "LdifData{" + "content='" + content + '\'' + '}';
    }
}
