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

package org.opensearch.security.privileges;

import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.indices.settings.get.GetSettingsRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;

/**
 * Defines which indices and documents are implicitly accessible although a user does not have
 * explicit permissions for it. This is required for executing TLQ in DLS queries. In this case
 * the user does not have direct access to the index for the term lookup. However, we need to allow
 * access for executing the actual TLQ. The document allow list is scoped to individual requests.
 */
public class DocumentAllowList {

    private static final Logger log = LogManager.getLogger(DocumentAllowList.class);

    public static final String WILDCARD_DOCUMENT_ID = "*";

    public static DocumentAllowList get(ThreadContext threadContext) {
        String header = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER);

        if (header == null) {
            return EMPTY;
        } else {
            try {
                return parse(header);
            } catch (Exception e) {
                log.error("Error while handling document allow list: {}", header, e);
                return EMPTY;
            }
        }
    }

    public static boolean isAllowed(ActionRequest request, ThreadContext threadContext) {
        final var documentAllowList = DocumentAllowList.get(threadContext);

        if (documentAllowList.isEmpty()) {
            return false;
        }

        // GetRequest: id-based TLQ resolves via GET; match exact (index, id) entry.
        // SearchRequest: query-based TLQ resolves via SEARCH; match wildcard entry.
        // GetSettingsRequest: OpenSearch reads index settings before executing query-based TLQ search.
        // Other request types (including writes) are never allowlisted.
        if (request instanceof GetRequest getRequest) {
            if (documentAllowList.isAllowed(getRequest.index(), getRequest.id())) {
                log.debug("Request {} is allowed by {}", request, documentAllowList);
                return true;
            }
            return false;
        } else if (request instanceof SearchRequest searchRequest) {
            if (isIndicesAllowlisted(documentAllowList, searchRequest.indices())) {
                log.debug("Request {} is allowed by {}", request, documentAllowList);
                return true;
            }
            return false;
        } else if (request instanceof GetSettingsRequest getSettingsRequest) {
            if (isIndicesAllowlisted(documentAllowList, getSettingsRequest.indices())) {
                log.debug("Request {} is allowed by {}", request, documentAllowList);
                return true;
            }
            return false;
        }

        return false;
    }

    // allMatch semantics: at privilege-evaluation time, every index in the request must be
    // covered. DlsFlsValveImpl uses anyMatch+size()==1 for a different purpose (per-shard bypass).
    private static boolean isIndicesAllowlisted(DocumentAllowList documentAllowList, String[] indices) {
        if (indices == null || indices.length == 0) {
            return false;
        }
        for (String index : indices) {
            if (index == null || !documentAllowList.isAllowed(index, WILDCARD_DOCUMENT_ID)) {
                return false;
            }
        }
        return true;
    }

    private static final DocumentAllowList EMPTY = new DocumentAllowList();

    private final Set<Entry> entries = new HashSet<>();

    public DocumentAllowList() {}

    public void add(String index, String id) {
        this.add(new Entry(index, id));
    }

    public void add(Entry entry) {
        this.entries.add(entry);
    }

    public boolean isEmpty() {
        return this.entries.isEmpty();
    }

    public void applyTo(ThreadContext threadContext) {
        if (!isEmpty()) {
            String value = toString();
            String existing = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER);

            if (existing != null) {
                if (existing.equals(value)) {
                    // Already applied
                    return;
                } else {
                    log.warn("Document allow list header is already present in thread context: {}", existing);
                    return;
                }
            }

            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, value);
        }
    }

    public boolean isAllowed(String index, String id) {
        for (Entry entry : entries) {
            if (entry.index.equals(index) && entry.id.equals(id)) {
                return true;
            }
        }

        return false;
    }

    public boolean isEntryForIndexPresent(String index) {
        for (Entry entry : entries) {
            if (entry.index.equals(index)) {
                return true;
            }
        }

        return false;
    }

    public String toString() {
        if (this.entries.isEmpty()) {
            return "";
        }

        StringBuilder stringBuilder = new StringBuilder();

        for (Entry entry : entries) {
            if (stringBuilder.length() != 0) {
                stringBuilder.append('|');
            }
            stringBuilder.append(entry.index).append("/").append(escapeId(entry.id));
        }

        return stringBuilder.toString();
    }

    public static DocumentAllowList parse(String string) {
        DocumentAllowList result = new DocumentAllowList();

        int length = string.length();

        if (length == 0) {
            return result;
        }

        int entryStart = 0;
        String index = null;

        for (int i = 0;; i++) {
            char c;

            if (i < length) {
                c = string.charAt(i);
            } else {
                c = '|';
            }

            while (c == '\\') {
                i += 2;
                c = string.charAt(i);
            }

            if (c == '/') {
                index = string.substring(entryStart, i);
                entryStart = i + 1;
            } else if (c == '|') {
                if (index == null) {
                    throw new IllegalArgumentException("Malformed DocumentAllowList string: " + string);
                }

                String id = unescapeId(string.substring(entryStart, i));

                result.add(index, id);
                index = null;
                entryStart = i + 1;
            }

            if (i >= length) {
                break;
            }
        }

        return result;
    }

    private static String escapeId(String id) {
        int length = id.length();
        boolean needsEscaping = false;

        for (int i = 0; i < length; i++) {
            char c = id.charAt(i);
            if (c == '/' || c == '|' || c == '\\') {
                needsEscaping = true;
                break;
            }
        }

        if (!needsEscaping) {
            return id;
        }

        StringBuilder result = new StringBuilder(id.length() + 10);

        for (int i = 0; i < length; i++) {
            char c = id.charAt(i);
            if (c == '/' || c == '|' || c == '\\') {
                result.append('\\');
            }
            result.append(c);
        }

        return result.toString();
    }

    private static String unescapeId(String id) {
        int length = id.length();
        boolean needsEscaping = false;

        for (int i = 0; i < length; i++) {
            char c = id.charAt(i);
            if (c == '\\') {
                needsEscaping = true;
                break;
            }
        }

        if (!needsEscaping) {
            return id;
        }

        StringBuilder result = new StringBuilder(id.length());

        for (int i = 0; i < length; i++) {
            char c = id.charAt(i);
            if (c == '\\') {
                i++;
                c = id.charAt(i);
            }

            result.append(c);
        }

        return result.toString();
    }

    public static class Entry {
        private final String index;
        private final String id;

        Entry(String index, String id) {
            if (index.indexOf('/') != -1 || index.indexOf('|') != -1) {
                throw new IllegalArgumentException("Invalid index name: " + index);
            }

            this.index = index;
            this.id = id;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((id == null) ? 0 : id.hashCode());
            result = prime * result + ((index == null) ? 0 : index.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            Entry other = (Entry) obj;
            if (id == null) {
                if (other.id != null) {
                    return false;
                }
            } else if (!id.equals(other.id)) {
                return false;
            }
            if (index == null) {
                if (other.index != null) {
                    return false;
                }
            } else if (!index.equals(other.index)) {
                return false;
            }
            return true;
        }

        @Override
        public String toString() {
            return "DocumentAllowList.Entry [index=" + index + ", id=" + id + "]";
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entries == null) ? 0 : entries.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        DocumentAllowList other = (DocumentAllowList) obj;
        if (entries == null) {
            if (other.entries != null) {
                return false;
            }
        } else if (!entries.equals(other.entries)) {
            return false;
        }
        return true;
    }
}
