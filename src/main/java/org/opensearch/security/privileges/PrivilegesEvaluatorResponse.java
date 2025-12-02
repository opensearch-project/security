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

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;

import com.selectivem.collections.CheckTable;

public class PrivilegesEvaluatorResponse {
    private final boolean allowed;
    private final CreateIndexRequestBuilder createIndexRequestBuilder;
    private final ImmutableSet<String> onlyAllowedForIndices;
    private final CheckTable<String, String> indexToActionCheckTable;
    private String privilegeMatrix;
    private final String reason;
    boolean shouldSkipDlsValve = false;

    /**
     * Contains issues that were encountered during privilege evaluation. Can be used for logging.
     */
    private ImmutableList<PrivilegesEvaluationException> evaluationExceptions;

    public PrivilegesEvaluatorResponse(
        boolean allowed,
        ImmutableSet<String> onlyAllowedForIndices,
        CheckTable<String, String> indexToActionCheckTable,
        String privilegeMatrix,
        String reason,
        ImmutableList<PrivilegesEvaluationException> evaluationExceptions,
        CreateIndexRequestBuilder createIndexRequestBuilder
    ) {
        this.allowed = allowed;
        this.createIndexRequestBuilder = createIndexRequestBuilder;
        this.onlyAllowedForIndices = onlyAllowedForIndices;
        this.indexToActionCheckTable = indexToActionCheckTable;
        this.privilegeMatrix = privilegeMatrix;
        this.reason = reason;
        this.evaluationExceptions = evaluationExceptions;
    }

    public PrivilegesEvaluatorResponse(
        boolean allowed,
        ImmutableSet<String> onlyAllowedForIndices,
        CheckTable<String, String> indexToActionCheckTable
    ) {
        this.allowed = allowed;
        this.createIndexRequestBuilder = null;
        this.onlyAllowedForIndices = onlyAllowedForIndices;
        this.indexToActionCheckTable = indexToActionCheckTable;
        this.privilegeMatrix = null;
        this.reason = null;
        this.evaluationExceptions = ImmutableList.of();
    }

    /**
     * Returns true if the request can be fully allowed. See also isAllowedForSpecificIndices().
     */
    public boolean isAllowed() {
        return allowed;
    }

    /**
     * Returns true if the request is only for dashboards indices
     */
    public boolean shouldSkipDlsValve() {
        return shouldSkipDlsValve;
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
        return new PrivilegesEvaluatorResponse(
            this.allowed,
            this.onlyAllowedForIndices,
            this.indexToActionCheckTable,
            this.privilegeMatrix,
            reason,
            this.evaluationExceptions,
            this.createIndexRequestBuilder
        );
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
        if (evaluationExceptions.isEmpty()) {
            return this;
        }
        return new PrivilegesEvaluatorResponse(
            this.allowed,
            this.onlyAllowedForIndices,
            this.indexToActionCheckTable,
            this.privilegeMatrix,
            this.reason,
            ImmutableList.<PrivilegesEvaluationException>builder().addAll(this.evaluationExceptions).addAll(evaluationExceptions).build(),
            this.createIndexRequestBuilder
        );
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

    public CreateIndexRequestBuilder getCreateIndexRequestBuilder() {
        return createIndexRequestBuilder;
    }

    public PrivilegesEvaluatorResponse with(CreateIndexRequestBuilder createIndexRequestBuilder) {
        if (createIndexRequestBuilder == this.createIndexRequestBuilder) {
            return this;
        }

        return new PrivilegesEvaluatorResponse(
            this.allowed,
            this.onlyAllowedForIndices,
            this.indexToActionCheckTable,
            this.privilegeMatrix,
            this.reason,
            this.evaluationExceptions,
            createIndexRequestBuilder
        );
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
        return new PrivilegesEvaluatorResponse(true, ImmutableSet.of(), null);
    }

    public static PrivilegesEvaluatorResponse partiallyOk(
        Set<String> availableIndices,
        CheckTable<String, String> indexToActionCheckTable
    ) {
        return new PrivilegesEvaluatorResponse(false, ImmutableSet.copyOf(availableIndices), indexToActionCheckTable);
    }

    public static PrivilegesEvaluatorResponse insufficient(String missingPrivilege) {
        return new PrivilegesEvaluatorResponse(
            false,
            ImmutableSet.of(),
            CheckTable.create(ImmutableSet.of("_"), ImmutableSet.of(missingPrivilege))
        );
    }

    public static PrivilegesEvaluatorResponse insufficient(CheckTable<String, String> indexToActionCheckTable) {
        return new PrivilegesEvaluatorResponse(false, ImmutableSet.of(), indexToActionCheckTable);
    }
}
