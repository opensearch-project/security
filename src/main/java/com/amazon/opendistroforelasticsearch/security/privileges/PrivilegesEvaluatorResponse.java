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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.privileges;

import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PrivilegesEvaluatorResponse {
    boolean allowed = false;
    Set<String> missingPrivileges = new HashSet<String>();
    Map<String,Set<String>> allowedFlsFields;
    Map<String,Set<String>> maskedFields;
    Map<String,Set<String>> queries;
    PrivilegesEvaluatorResponseState state = PrivilegesEvaluatorResponseState.PENDING;
    CreateIndexRequestBuilder createIndexRequestBuilder;
    
    public boolean isAllowed() {
        return allowed;
    }
    public Set<String> getMissingPrivileges() {
        return new HashSet<String>(missingPrivileges);
    }

    public Map<String,Set<String>> getAllowedFlsFields() {
        return allowedFlsFields;
    }
    
    public Map<String,Set<String>> getMaskedFields() {
        return maskedFields;
    }

    public Map<String,Set<String>> getQueries() {
        return queries;
    }

    public CreateIndexRequestBuilder getCreateIndexRequestBuilder() {
        return createIndexRequestBuilder;
    }
    
    public PrivilegesEvaluatorResponse markComplete() {
        this.state = PrivilegesEvaluatorResponseState.COMPLETE;
        return this;
    }

    public PrivilegesEvaluatorResponse markPending() {
        this.state = PrivilegesEvaluatorResponseState.PENDING;
        return this;
    }

    public boolean isComplete() {
        return this.state == PrivilegesEvaluatorResponseState.COMPLETE;
    }

    public boolean isPending() {
        return this.state == PrivilegesEvaluatorResponseState.PENDING;
    }

    @Override
    public String toString() {
        return "PrivEvalResponse [allowed=" + allowed + ", missingPrivileges=" + missingPrivileges
                + ", allowedFlsFields=" + allowedFlsFields + ", maskedFields=" + maskedFields + ", queries=" + queries + "]";
    }
    
    public static enum PrivilegesEvaluatorResponseState {
        PENDING,
        COMPLETE;
    }
    
}