/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.floragunn.searchguard.support;

import java.io.Serializable;
import java.util.Arrays;

import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.search.SearchRequest;

public class SourceFieldsContext implements Serializable {

    private String[] includes;
    private String[] excludes;
    private String[] storedFields;
    private boolean fetchSource = true;

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static boolean isNeeded(SearchRequest request) {
        return (request.source() != null && request.source().fetchSource() != null && (request.source().fetchSource().includes() != null || request
                .source().fetchSource().excludes() != null))
                || (request.source() != null && request.source().storedFields() != null
                        && request.source().storedFields().fieldNames() != null && !request.source().storedFields().fieldNames().isEmpty());
    }

    public static boolean isNeeded(GetRequest request) {
        return (request.fetchSourceContext() != null && (request.fetchSourceContext().includes() != null || request.fetchSourceContext()
                .excludes() != null)) || (request.storedFields() != null && request.storedFields().length > 0);
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

        if (request.source() != null && request.source().storedFields() != null && request.source().storedFields().fieldNames() != null) {
            storedFields = request.source().storedFields().fieldNames().toArray(new String[0]);
        }
    }

    public SourceFieldsContext(GetRequest request) {
        if (request.fetchSourceContext() != null) {
            includes = request.fetchSourceContext().includes();
            excludes = request.fetchSourceContext().excludes();
            fetchSource = request.fetchSourceContext().fetchSource();
        }

        storedFields = request.storedFields();
    }

    public String[] getIncludes() {
        return includes;
    }

    public void setIncludes(String[] includes) {
        this.includes = includes;
    }

    public String[] getExcludes() {
        return excludes;
    }

    public void setExcludes(String[] excludes) {
        this.excludes = excludes;
    }

    public String[] getStoredFields() {
        return storedFields;
    }

    public void setStoredFields(String[] storedFields) {
        this.storedFields = storedFields;
    }

    public boolean isFetchSource() {
        return fetchSource;
    }

    public void setFetchSource(boolean fetchSource) {
        this.fetchSource = fetchSource;
    }

    @Override
    public String toString() {
        return "SourceFieldsContext [includes=" + Arrays.toString(includes) + ", excludes=" + Arrays.toString(excludes) + ", storedFields="
                + Arrays.toString(storedFields) + ", fetchSource=" + fetchSource + "]";
    }
}
