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

import java.util.Objects;
import java.util.function.Supplier;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

/**
 * The basic interface for privilege evaluation.
 */
public interface PrivilegesEvaluator {

    default PrivilegesEvaluationContext createContext(User user, String action) {
        return createContext(user, action, null, ActionRequestMetadata.empty(), null);
    }

    PrivilegesEvaluationContext createContext(
        User user,
        String action,
        ActionRequest actionRequest,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        Task task
    );

    PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context);

    boolean isClusterPermission(String action);

    void updateConfiguration(
        FlattenedActionGroups actionGroups,
        CompiledRoles rolesConfiguration,
        GlobalDynamicSettings globalDynamicSettings
    );

    void updateClusterStateMetadata(ClusterService clusterService);

    /**
     * Shuts down any background processes or other resources that need an explicit shut down
     */
    void shutdown();

    boolean notFailOnForbiddenEnabled();

    PrivilegesEvaluatorType type();

    enum PrivilegesEvaluatorType {
        NOT_INITIALIZED,
        STANDARD
    }

    /**
     * A PrivilegesEvaluator implementation that just throws "not initialized" exceptions.
     * Used initially by PrivilegesConfiguration.
     */
    class NotInitialized implements PrivilegesEvaluator {
        private final Supplier<String> unavailablityReasonSupplier;

        NotInitialized(Supplier<String> unavailablityReasonSupplier) {
            this.unavailablityReasonSupplier = unavailablityReasonSupplier;
        }

        @Override
        public PrivilegesEvaluatorType type() {
            return PrivilegesEvaluatorType.NOT_INITIALIZED;
        }

        @Override
        public PrivilegesEvaluationContext createContext(
            User user,
            String action,
            ActionRequest actionRequest,
            ActionRequestMetadata<?, ?> actionRequestMetadata,
            Task task
        ) {
            throw exception();
        }

        @Override
        public PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context) {
            throw exception();
        }

        @Override
        public boolean isClusterPermission(String action) {
            return false;
        }

        @Override
        public void updateConfiguration(
            FlattenedActionGroups actionGroups,
            CompiledRoles rolesConfiguration,
            GlobalDynamicSettings globalDynamicSettings
        ) {

        }

        @Override
        public void updateClusterStateMetadata(ClusterService clusterService) {

        }

        @Override
        public void shutdown() {

        }

        @Override
        public boolean notFailOnForbiddenEnabled() {
            return false;
        }

        private OpenSearchSecurityException exception() {
            StringBuilder error = new StringBuilder("OpenSearch Security not initialized");
            String reason = this.unavailablityReasonSupplier.get();

            if (reason != null) {
                error.append(": ").append(reason);
            } else {
                error.append(".");
            }

            return new OpenSearchSecurityException(error.toString(), RestStatus.SERVICE_UNAVAILABLE);
        }
    };

    /**
     * Configuration that is sourced from the "general purpose mixed bag" configuration type called config.
     * The purpose of this class is to provide a focused view to the needed settings.
     */
    class GlobalDynamicSettings {
        final boolean dnfofEnabled;
        final boolean dnfofForEmptyResultsEnabled;
        final String filteredAliasMode;

        GlobalDynamicSettings(boolean dnfofEnabled, boolean dnfofForEmptyResultsEnabled, String filteredAliasMode) {
            this.dnfofEnabled = dnfofEnabled;
            this.dnfofForEmptyResultsEnabled = dnfofForEmptyResultsEnabled;
            this.filteredAliasMode = filteredAliasMode;
        }

        public static GlobalDynamicSettings fromConfigV7(ConfigV7 configV7) {
            return new GlobalDynamicSettings(isDnfofEnabled(configV7), isDnfofEmptyEnabled(configV7), getFilteredAliasMode(configV7));
        }

        private static boolean isDnfofEnabled(ConfigV7 generalConfiguration) {
            return generalConfiguration.dynamic != null && generalConfiguration.dynamic.do_not_fail_on_forbidden;
        }

        private static boolean isDnfofEmptyEnabled(ConfigV7 generalConfiguration) {
            return generalConfiguration.dynamic != null && generalConfiguration.dynamic.do_not_fail_on_forbidden_empty;
        }

        private static String getFilteredAliasMode(ConfigV7 generalConfiguration) {
            return generalConfiguration.dynamic != null ? generalConfiguration.dynamic.filtered_alias_mode : "none";
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof GlobalDynamicSettings that)) {
                return false;
            }
            return dnfofEnabled == that.dnfofEnabled
                && dnfofForEmptyResultsEnabled == that.dnfofForEmptyResultsEnabled
                && Objects.equals(filteredAliasMode, that.filteredAliasMode);
        }

        @Override
        public int hashCode() {
            return Objects.hash(dnfofEnabled, dnfofForEmptyResultsEnabled, filteredAliasMode);
        }
    }
}
