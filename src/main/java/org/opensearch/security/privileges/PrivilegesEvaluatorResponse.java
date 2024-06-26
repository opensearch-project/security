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

package org.opensearch.security.privileges;

import java.util.HashSet;
import java.util.Set;

import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;

public class PrivilegesEvaluatorResponse {
    boolean allowed = false;
    Set<String> missingPrivileges = new HashSet<String>();
    Set<String> missingSecurityRoles = new HashSet<>();
    Set<String> resolvedSecurityRoles = new HashSet<>();
    PrivilegesEvaluatorResponseState state = PrivilegesEvaluatorResponseState.PENDING;
    CreateIndexRequestBuilder createIndexRequestBuilder;
    private String reason;

    public boolean isAllowed() {
        return allowed;
    }

    public Set<String> getMissingPrivileges() {
        return new HashSet<String>(missingPrivileges);
    }

    public Set<String> getMissingSecurityRoles() {
        return new HashSet<>(missingSecurityRoles);
    }

    public Set<String> getResolvedSecurityRoles() {
        return new HashSet<>(resolvedSecurityRoles);
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

    public String getReason() {
        return this.reason;
    }

    public PrivilegesEvaluatorResponse reason(String reason) {
        this.reason = reason;
        return this;
    }

    @Override
    public String toString() {
        return "PrivEvalResponse [allowed=" + allowed + ", missingPrivileges=" + missingPrivileges + "]";
    }

    public static enum PrivilegesEvaluatorResponseState {
        PENDING,
        COMPLETE;
    }

    /**
     * This exception can be used to indicate that a method denies a user access to an OpenSearch action.
     *
     * Note: As exceptions take their performance toll, please use this exception only when there is
     * no other way. Prefer to use PrivilegesEvaluatorResponse directly as a return value.
     */
    public static class NotAllowedException extends Exception {
        private final PrivilegesEvaluatorResponse response;

        public NotAllowedException(PrivilegesEvaluatorResponse response) {
            super(response.reason);
            this.response = response;
            if (response.allowed) {
                throw new IllegalArgumentException("Only possible for PrivilegesEvaluatorResponse with allowed=false");
            }
        }

        public PrivilegesEvaluatorResponse getResponse() {
            return response;
        }
    }

}
