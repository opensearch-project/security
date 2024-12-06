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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;

import com.selectivem.collections.CheckTable;

public class PrivilegesEvaluatorResponse {
    boolean allowed = false;
    Set<String> missingSecurityRoles = new HashSet<>();
    PrivilegesEvaluatorResponseState state = PrivilegesEvaluatorResponseState.PENDING;
    CreateIndexRequestBuilder createIndexRequestBuilder;
    private Set<String> onlyAllowedForIndices = ImmutableSet.of();
    private CheckTable<String, String> indexToActionCheckTable;
    private String privilegeMatrix;
    private String reason;

    /**
     * Contains issues that were encountered during privilege evaluation. Can be used for logging.
     */
    private List<PrivilegesEvaluationException> evaluationExceptions = new ArrayList<>();

    /**
     * Returns true if the request can be fully allowed. See also isAllowedForSpecificIndices().
     */
    public boolean isAllowed() {
        return allowed;
    }

    /**
     * Returns true if the request can be allowed if the referenced indices are reduced (aka "do not fail on forbidden").
     * See getAvailableIndices() for the indices for which we have privileges.
     */
    public boolean isPartiallyOk() {
        return !this.onlyAllowedForIndices.isEmpty();
    }

    /**
     * In case isPartiallyOk() is true, this returns the indices for which we have privileges.
     */
    public Set<String> getAvailableIndices() {
        return this.onlyAllowedForIndices;
    }

    /**
     * In case isAllowed() is false, this returns the privileges (aka action names) for which we do not have sufficient
     * privileges.
     */
    public Set<String> getMissingPrivileges() {
        return this.indexToActionCheckTable != null ? this.indexToActionCheckTable.getIncompleteColumns() : Collections.emptySet();
    }

    /**
     * Returns a human-readable reason for the missing privilege. Can be used to make the error message more easy
     * to understand.
     */
    public String getReason() {
        return this.reason;
    }

    public PrivilegesEvaluatorResponse reason(String reason) {
        this.reason = reason;
        return this;
    }

    /**
     * Returns a diagnostic string that contains issues that were encountered during privilege evaluation. Can be used for logging.
     */
    public String getEvaluationExceptionInfo() {
        StringBuilder result = new StringBuilder("Exceptions encountered during privilege evaluation:\n");

        for (PrivilegesEvaluationException evaluationException : this.evaluationExceptions) {
            result.append(evaluationException.getNestedMessages()).append("\n");
        }

        return result.toString();
    }

    public boolean hasEvaluationExceptions() {
        return !evaluationExceptions.isEmpty();
    }

    public PrivilegesEvaluatorResponse evaluationExceptions(Collection<PrivilegesEvaluationException> evaluationExceptions) {
        this.evaluationExceptions.addAll(evaluationExceptions);
        return this;
    }

    /**
     * Returns an ASCII string showing a matrix of available/missing privileges.
     * Rows represent indices, columns represent actions.
     */
    public String getPrivilegeMatrix() {
        String result = this.privilegeMatrix;

        if (result == null) {
            result = this.indexToActionCheckTable.toTableString("ok", "MISSING");
            this.privilegeMatrix = result;
        }
        return result;
    }

    public Set<String> getMissingSecurityRoles() {
        return new HashSet<>(missingSecurityRoles);
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
        return "PrivEvalResponse [\nallowed="
            + allowed
            + ",\nonlyAllowedForIndices="
            + onlyAllowedForIndices
            + ",\n"
            + (indexToActionCheckTable != null ? indexToActionCheckTable.toTableString("ok", "MISSING") : "")
            + "]";
    }

    public static PrivilegesEvaluatorResponse ok() {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.allowed = true;
        return response;
    }

    public static PrivilegesEvaluatorResponse partiallyOk(
        Set<String> availableIndices,
        CheckTable<String, String> indexToActionCheckTable
    ) {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.onlyAllowedForIndices = ImmutableSet.copyOf(availableIndices);
        response.indexToActionCheckTable = indexToActionCheckTable;
        return response;
    }

    public static PrivilegesEvaluatorResponse insufficient(String missingPrivilege) {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.indexToActionCheckTable = CheckTable.create(ImmutableSet.of("_"), ImmutableSet.of(missingPrivilege));
        return response;
    }

    public static PrivilegesEvaluatorResponse insufficient(CheckTable<String, String> indexToActionCheckTable) {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.indexToActionCheckTable = indexToActionCheckTable;
        return response;
    }

    public static enum PrivilegesEvaluatorResponseState {
        PENDING,
        COMPLETE;
    }

}
