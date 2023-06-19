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

import java.util.Objects;

public class RecordBuilder {

    private final LdifBuilder builder;
    private final Record record;

    RecordBuilder(LdifBuilder builder, String distinguishedName) {
        this.builder = Objects.requireNonNull(builder, "LdifBuilder is required");
        this.record = new Record(distinguishedName);
    }

    public RecordBuilder classes(String... classes) {
        for (String clazz : classes) {
            this.record.addClass(clazz);
        }
        return this;
    }

    public RecordBuilder dn(String distinguishedName) {
        record.addAttribute("dn", distinguishedName);
        return this;
    }

    public RecordBuilder dc(String domainComponent) {
        record.addAttribute("dc", domainComponent);
        return this;
    }

    public RecordBuilder ou(String organizationUnit) {
        record.addAttribute("ou", organizationUnit);
        return this;
    }

    public RecordBuilder cn(String commonName) {
        record.addAttribute("cn", commonName);
        return this;
    }

    public RecordBuilder sn(String surname) {
        record.addAttribute("sn", surname);
        return this;
    }

    public RecordBuilder uid(String userId) {
        record.addAttribute("uid", userId);
        return this;
    }

    public RecordBuilder userPassword(String password) {
        record.addAttribute("userpassword", password);
        return this;
    }

    public RecordBuilder mail(String emailAddress) {
        record.addAttribute("mail", emailAddress);
        return this;
    }

    public RecordBuilder uniqueMember(String userDistinguishedName) {
        record.addAttribute("uniquemember", userDistinguishedName);
        return this;
    }

    public RecordBuilder attribute(String name, String value) {
        record.addAttribute(name, value);
        return this;
    }

    public LdifBuilder buildRecord() {
        if (record.isValid() == false) {
            throw new IllegalStateException("Record is invalid");
        }
        builder.addRecord(record);
        return builder;
    }

    public RecordBuilder newRecord(String distinguishedName) {
        return buildRecord().newRecord(distinguishedName);
    }
}
