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

import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.action.apitokens.ApiTokenRepository;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.actionlevel.SubjectBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.legacy.PrivilegesEvaluatorImpl;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

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

    void updateClusterStateMetadata(Supplier<ClusterState> clusterStateSupplier);

    /**
     * Shuts down any background processes or other resources that need an explicit shut down
     */
    void shutdown();

    boolean notFailOnForbiddenEnabled();

    PrivilegesEvaluatorType type();

    @SuppressWarnings("deprecation")
    enum PrivilegesEvaluatorType {
        NOT_INITIALIZED((c, d) -> new NotInitialized(c)),
        LEGACY(PrivilegesEvaluatorImpl::new),
        V4(org.opensearch.security.privileges.actionlevel.nextgen.PrivilegesEvaluatorImpl::new);

        static PrivilegesEvaluatorType getFrom(SecurityDynamicConfiguration<ConfigV7> configConfig) {
            final PrivilegesEvaluatorType defaultValue = LEGACY;

            if (configConfig == null) {
                return defaultValue;
            }

            ConfigV7 config = configConfig.getCEntry(CType.CONFIG.name());
            if (config == null || config.dynamic == null) {
                return defaultValue;
            }
            if (V4.name().equalsIgnoreCase(config.dynamic.privilegesEvaluationType)) {
                return V4;
            } else {
                return LEGACY;
            }
        }

        final Factory factory;

        PrivilegesEvaluatorType(Factory factory) {
            this.factory = factory;
        }
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

        NotInitialized(CoreDependencies coreDependencies) {
            this(coreDependencies.unavailablityReasonSupplier());
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
        public void updateClusterStateMetadata(Supplier<ClusterState> clusterStateSupplier) {}

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
     * <p>
     * Most of the options are only supported by the legacy privileges evaluator. This is on purpose
     * as these configuration options are just for providing backwards compatibility without breaking changes.
     * The new privilege evaluation does breaking changes to shed off old baggage.
     */
    class GlobalDynamicSettings {
        /**
         * This is a successor to the do_not_fail_on_forbidden property; it is only evaluated if
         * privilegesEvaluationType is set to "v4"; we cannot reuse the old property as it we cannot change
         * the default value of it based on privileges_evaluation_type.
         * This should be only very rarely set to "false"; if it is false, users must make sure that they
         * are not hitting any unauthorized indices in their patterns, including system indices, as otherwise these requests
         * will just fail.
         */
        public final boolean ignoreUnauthorizedIndices;

        /**
         * Only supported by legacy privilege evaluation. See ignoreUnauthorizedIndices for replacement.
         */
        public final boolean dnfofEnabled;

        /**
         * Only supported by legacy privilege evaluation..
         */
        public final boolean dnfofForEmptyResultsEnabled;

        /**
         * Only supported by legacy privilege evaluation..
         */
        public final String filteredAliasMode;

        /**
         * Only supported by legacy privilege evaluation..
         */
        public final boolean respectRequestIndicesOptions;

        GlobalDynamicSettings(
            boolean ignoreUnauthorizedIndices,
            boolean dnfofEnabled,
            boolean dnfofForEmptyResultsEnabled,
            String filteredAliasMode,
            boolean respectRequestIndicesOptions
        ) {
            this.ignoreUnauthorizedIndices = ignoreUnauthorizedIndices;
            this.dnfofEnabled = dnfofEnabled;
            this.dnfofForEmptyResultsEnabled = dnfofForEmptyResultsEnabled;
            this.filteredAliasMode = filteredAliasMode;
            this.respectRequestIndicesOptions = respectRequestIndicesOptions;
        }

        public static GlobalDynamicSettings fromConfigV7(ConfigV7 configV7) {
            return new GlobalDynamicSettings(
                isIndexReductionEnabled(configV7),
                isDnfofEnabled(configV7),
                isDnfofEmptyEnabled(configV7),
                getFilteredAliasMode(configV7),
                isRespectRequestIndicesOptionsEnabled(configV7)
            );
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

        private static boolean isRespectRequestIndicesOptionsEnabled(ConfigV7 generalConfiguration) {
            return generalConfiguration.dynamic != null && generalConfiguration.dynamic.respect_request_indices_options;
        }

        private static boolean isIndexReductionEnabled(ConfigV7 generalConfiguration) {
            return generalConfiguration.dynamic == null || generalConfiguration.dynamic.privilegesEvaluationIgnoreUnauthorizedIndices;
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

    /**
     * Dependencies for PrivilegeEvaluator implementations that are cluster global and never change during the
     * cluster lifecycle.
     */
    record CoreDependencies(ClusterService clusterService, Supplier<ClusterState> clusterStateSupplier, Client client,
        RoleMapper roleMapper, ThreadPool threadPool, ThreadContext threadContext, AuditLog auditLog, Settings settings,
        IndexNameExpressionResolver indexNameExpressionResolver, Supplier<String> unavailablityReasonSupplier,
        NamedXContentRegistry namedXContentRegistry, ApiTokenRepository apiTokenRepository) {
    }

    /**
     * Dependencies for PrivilegeEvaluator implementations that can change during the cluster lifecycle or which are
     * not cluster global, but rather scoped to the PrivilegeConfiguration instance.
     */
    record DynamicDependencies(FlattenedActionGroups actionGroups, FlattenedActionGroups staticActionGroups,
        CompiledRoles rolesConfiguration, PrivilegesEvaluator.GlobalDynamicSettings generalConfiguration, SpecialIndices specialIndices,
        Supplier<TenantPrivileges> tenantPrivilegesSupplier, Supplier<
            DashboardsMultiTenancyConfiguration> multiTenancyConfigurationSupplier, Map<
                String,
                SubjectBasedActionPrivileges.PrivilegeSpecification> pluginIdToPrivileges, Map<
                    String,
                    ActionPrivileges> tokenIdToActionPrivileges) {

        public static final DynamicDependencies EMPTY = new PrivilegesEvaluator.DynamicDependencies(
            FlattenedActionGroups.EMPTY,
            FlattenedActionGroups.EMPTY,
            CompiledRoles.EMPTY,
            new GlobalDynamicSettings(true, false, false, "none", false),
            new SpecialIndices(Settings.EMPTY),
            () -> TenantPrivileges.EMPTY,
            () -> DashboardsMultiTenancyConfiguration.DEFAULT,
            Map.of(),
            Map.of()
        );

        public DynamicDependencies with(CompiledRoles roles) {
            return new DynamicDependencies(
                actionGroups,
                staticActionGroups,
                roles,
                generalConfiguration,
                specialIndices,
                tenantPrivilegesSupplier,
                multiTenancyConfigurationSupplier,
                pluginIdToPrivileges,
                tokenIdToActionPrivileges
            );
        }

        public DynamicDependencies with(Map<String, SubjectBasedActionPrivileges.PrivilegeSpecification> pluginIdToPrivileges) {
            return new DynamicDependencies(
                actionGroups,
                staticActionGroups,
                this.rolesConfiguration,
                generalConfiguration,
                specialIndices,
                tenantPrivilegesSupplier,
                multiTenancyConfigurationSupplier,
                pluginIdToPrivileges,
                tokenIdToActionPrivileges
            );
        }

    }

    @FunctionalInterface
    interface Factory {
        PrivilegesEvaluator create(CoreDependencies coreDependencies, DynamicDependencies dynamicDependencies);
    }

}
