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
import java.util.List;
import java.util.Objects;
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
    private ImmutableList<PrivilegesEvaluatorResponse> subResults;

    /**
     * If the result was modified, i.e., it was changed from partially ok to ok, because the indices were reduced,
     * this contains the result before modification.
     */
    private final PrivilegesEvaluatorResponse originalResult;

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
        CreateIndexRequestBuilder createIndexRequestBuilder,
        PrivilegesEvaluatorResponse originalResult,
        ImmutableList<PrivilegesEvaluatorResponse> subResults
    ) {
        this.allowed = allowed;
        this.createIndexRequestBuilder = createIndexRequestBuilder;
        this.onlyAllowedForIndices = onlyAllowedForIndices;
        this.indexToActionCheckTable = indexToActionCheckTable;
        this.privilegeMatrix = privilegeMatrix;
        this.reason = reason;
        this.evaluationExceptions = evaluationExceptions;
        this.originalResult = originalResult;
        this.subResults = subResults;
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
        this.originalResult = null;
        this.subResults = ImmutableList.of();
    }

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
        return new PrivilegesEvaluatorResponse(
            this.allowed,
            this.onlyAllowedForIndices,
            this.indexToActionCheckTable,
            this.privilegeMatrix,
            reason,
            this.evaluationExceptions,
            this.createIndexRequestBuilder,
            this.originalResult,
            this.subResults
        );
    }

    /**
     * Returns a diagnostic string that contains issues that were encountered during privilege evaluation. Can be used for logging.
     */
    public String getEvaluationExceptionInfo() {
        if (this.evaluationExceptions.isEmpty()) {
            return "";
        }

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
            this.createIndexRequestBuilder,
            this.originalResult,
            this.subResults
        );
    }

    /**
     * Returns an ASCII string showing a matrix of available/missing privileges.
     * Rows represent indices, columns represent actions.
     */
    public String getPrivilegeMatrix() {
        String result = this.privilegeMatrix;

        if (result == null) {
            String topLevelMatrix;

            if (this.indexToActionCheckTable != null) {
                topLevelMatrix = this.indexToActionCheckTable.toTableString("ok", "MISSING");
            } else {
                topLevelMatrix = "n/a";
            }

            if (subResults.isEmpty()) {
                result = topLevelMatrix;
            } else {
                StringBuilder resultBuilder = new StringBuilder(topLevelMatrix);
                for (PrivilegesEvaluatorResponse subResult : subResults) {
                    resultBuilder.append("\n");
                    resultBuilder.append(subResult.getPrivilegeMatrix());
                }
                result = resultBuilder.toString();
            }
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
            createIndexRequestBuilder,
            this.originalResult,
            this.subResults
        );
    }

    public PrivilegesEvaluatorResponse originalResult() {
        return this.originalResult;
    }

    public PrivilegesEvaluatorResponse originalResult(PrivilegesEvaluatorResponse originalResult) {
        if (originalResult != null) {
            ImmutableList<PrivilegesEvaluationException> evaluationExceptions = this.evaluationExceptions;
            if (!originalResult.evaluationExceptions.isEmpty()) {
                evaluationExceptions = ImmutableList.<PrivilegesEvaluationException>builder()
                    .addAll(evaluationExceptions)
                    .addAll(originalResult.evaluationExceptions)
                    .build();
            }

            return new PrivilegesEvaluatorResponse(
                this.allowed,
                this.onlyAllowedForIndices,
                this.indexToActionCheckTable,
                this.privilegeMatrix,
                this.reason,
                evaluationExceptions,
                this.createIndexRequestBuilder,
                originalResult,
                this.subResults
            );
        } else {
            return this;
        }
    }

    /**
     * Returns true if we have all the privileges for the request without having to reduce indices inside the request.
     */
    public boolean privilegesAreComplete() {
        if (originalResult != null && !originalResult.privilegesAreComplete()) {
            return false;
        } else if (indexToActionCheckTable != null && !indexToActionCheckTable.isComplete()) {
            return false;
        } else if (!subResults.isEmpty() && subResults.stream().anyMatch(subResult -> !subResult.privilegesAreComplete())) {
            return false;
        } else {
            return this.allowed;
        }
    }

    /**
     * Marks an existing response (potentially ok or partially ok) as insufficient due to missing privileges in sub-results.
     */
    public PrivilegesEvaluatorResponse insufficient(List<PrivilegesEvaluatorResponse> subResults) {
        return new PrivilegesEvaluatorResponse(
            false,
            ImmutableSet.of(),
            this.indexToActionCheckTable,
            this.privilegeMatrix,
            this.reason != null
                ? this.reason
                : subResults.stream().map(result -> result.reason).filter(Objects::nonNull).findFirst().orElse(null),
            this.evaluationExceptions,
            this.createIndexRequestBuilder,
            this.originalResult,
            ImmutableList.<PrivilegesEvaluatorResponse>builder().addAll(this.subResults).addAll(subResults).build()
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

    public static PrivilegesEvaluatorResponse ok(CheckTable<String, String> indexToActionCheckTable) {
        return new PrivilegesEvaluatorResponse(true, ImmutableSet.of(), indexToActionCheckTable);
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
