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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

class Record {

    private final String distinguishedName;

    private final List<String> classes;
    private final List<Pair<String, String>> attributes;

    public Record(String distinguishedName) {
        this.distinguishedName = Objects.requireNonNull(distinguishedName, "Distinguished name is required");
        this.classes = new ArrayList<>();
        this.attributes = new ArrayList<>();
    }

    public String getDistinguishedName() {
        return distinguishedName;
    }

    public void addClass(String clazz) {
        classes.add(Objects.requireNonNull(clazz, "Object class is required."));
    }

    public void addAttribute(String name, String value) {
        Objects.requireNonNull(name, "Attribute name is required");
        Objects.requireNonNull(value, "Attribute value is required");
        attributes.add(Pair.of(name, value));
    }

    boolean isValid() {
        return classes.size() > 0;
    }

    String toLdifRepresentation() {
        return new StringBuilder("dn: ").append(distinguishedName)
            .append("\n")
            .append(formattedClasses())
            .append("\n")
            .append(formattedAttributes())
            .append("\n")
            .toString();
    }

    private String formattedAttributes() {
        return attributes.stream().map(pair -> pair.getKey() + ": " + pair.getValue()).collect(Collectors.joining("\n"));
    }

    private String formattedClasses() {
        return classes.stream().map(clazz -> "objectClass: " + clazz).collect(Collectors.joining("\n"));
    }
}
