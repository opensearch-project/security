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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LdifBuilder {

    private static final Logger log = LogManager.getLogger(LdifBuilder.class);

    private final List<Record> records;

    private Record root;

    public LdifBuilder() {
        this.records = new ArrayList<>();
    }

    public RecordBuilder root(String distinguishedName) {
        if (root != null) {
            throw new IllegalStateException("Root object is already defined");
        }
        return new RecordBuilder(this, distinguishedName);
    }

    RecordBuilder newRecord(String distinguishedName) {
        if (root == null) {
            throw new IllegalStateException("Define root object first");
        }
        return new RecordBuilder(this, distinguishedName);
    }

    void addRecord(Record record) {
        Objects.requireNonNull(record, "Cannot add null record");
        if (records.isEmpty()) {
            this.root = record;
        }
        records.add(Objects.requireNonNull(record, "Cannot add null record"));
    }

    public LdifData buildLdif() {
        String ldif = records.stream().map(record -> record.toLdifRepresentation()).collect(Collectors.joining("\n##########\n"));
        log.debug("Built ldif file: \n{}", ldif);
        return new LdifData(getRootDistinguishedName(), ldif);
    }

    private String getRootDistinguishedName() {
        if (root == null) {
            throw new IllegalStateException("Root object is not present.");
        }
        return root.getDistinguishedName();
    }
}
