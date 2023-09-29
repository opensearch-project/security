/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.support;

import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;

public class SourceFieldsContext implements Serializable, Writeable {

    private String[] includes;
    private String[] excludes;
    // private String[] storedFields;
    private boolean fetchSource = true;

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static boolean isNeeded(SearchRequest request) {
        return (request.source() != null
            && request.source().fetchSource() != null
            && (request.source().fetchSource().includes() != null || request.source().fetchSource().excludes() != null))
            || (request.source() != null
                && request.source().storedFields() != null
                && request.source().storedFields().fieldNames() != null
                && !request.source().storedFields().fieldNames().isEmpty());
    }

    public static boolean isNeeded(GetRequest request) {
        return (request.fetchSourceContext() != null
            && (request.fetchSourceContext().includes() != null || request.fetchSourceContext().excludes() != null))
            || (request.storedFields() != null && request.storedFields().length > 0);
    }

    public SourceFieldsContext() {
        super();
    }

    public SourceFieldsContext(SearchRequest request) {
        if (request.source() != null && request.source().fetchSource() != null) {
            includes = request.source().fetchSource().includes();
            excludes = request.source().fetchSource().excludes();
            fetchSource = request.source().fetchSource().fetchSource();
        }

        // if (request.source() != null && request.source().storedFields() != null && request.source().storedFields().fieldNames() != null)
        // {
        // storedFields = request.source().storedFields().fieldNames().toArray(new String[0]);
        // }
    }

    public SourceFieldsContext(StreamInput in) throws IOException {
        includes = in.readStringArray();
        if (includes.length == 0) {
            includes = null;
        }
        excludes = in.readStringArray();
        if (excludes.length == 0) {
            excludes = null;
        }
        fetchSource = in.readBoolean();
    }

    public SourceFieldsContext(GetRequest request) {
        if (request.fetchSourceContext() != null) {
            includes = request.fetchSourceContext().includes();
            excludes = request.fetchSourceContext().excludes();
            fetchSource = request.fetchSourceContext().fetchSource();
        }

        // storedFields = request.storedFields();
    }

    public String[] getIncludes() {
        return includes;
    }

    public String[] getExcludes() {
        return excludes;
    }

    // public String[] getStoredFields() {
    // return storedFields;
    // }

    public boolean hasIncludesOrExcludes() {
        return (includes != null && includes.length > 0) || (excludes != null && excludes.length > 0);
    }

    public boolean isFetchSource() {
        return fetchSource;
    }

    @Override
    public String toString() {
        return "SourceFieldsContext [includes="
            + Arrays.toString(includes)
            + ", excludes="
            + Arrays.toString(excludes)
            + ", fetchSource="
            + fetchSource
            + "]";
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {
        streamOutput.writeStringArray(Objects.requireNonNullElseGet(includes, () -> new String[] {}));
        streamOutput.writeStringArray(Objects.requireNonNullElseGet(excludes, () -> new String[] {}));
        streamOutput.writeBoolean(fetchSource);
    }
}
