/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.privileges;

import java.util.HashSet;
import java.util.Set;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;

/**
 * Defines which indices and documents are implicitly accessible although a user does not have
 * explicit permissions for it. This is required for executing TLQ in DLS queries. In this case
 * the user does not have direct access to the index for the term lookup. However, we need to allow
 * access for executing the actual TLQ. The document allow list is scoped to individual requests.
 */
public class DocumentAllowList {

    private final Set<Entry> entries = new HashSet<>();

    public DocumentAllowList() {

    }

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
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, toString());
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
