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
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.actionlevel.SubjectBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.legacy.PrivilegesEvaluatorImpl;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
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
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
        ConfigV7 generalConfiguration
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
        NEXT_GEN(org.opensearch.security.privileges.actionlevel.nextgen.PrivilegesEvaluatorImpl::new);

        static PrivilegesEvaluatorType getFrom(SecurityDynamicConfiguration<ConfigV7> configConfig) {
            final PrivilegesEvaluatorType defaultValue = LEGACY;

            if (configConfig == null) {
                return defaultValue;
            }

            ConfigV7 config = configConfig.getCEntry(CType.CONFIG.name());
            if (config == null || config.dynamic == null) {
                return defaultValue;
            }
            if (NEXT_GEN.name().equalsIgnoreCase(config.dynamic.privilegesEvaluationType)) {
                return NEXT_GEN;
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
            SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
            ConfigV7 generalConfiguration
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
     * Dependencies for PrivilegeEvaluator implementations that are cluster global and never change during the
     * cluster lifecycle.
     */
    record CoreDependencies(ClusterService clusterService, Supplier<ClusterState> clusterStateSupplier, Client client,
        RoleMapper roleMapper, ThreadPool threadPool, ThreadContext threadContext, AuditLog auditLog, Settings settings,
        IndexNameExpressionResolver indexNameExpressionResolver, Supplier<String> unavailablityReasonSupplier

    ) {
    }

    /**
     * Dependencies for PrivilegeEvaluator implementations that can change during the cluster lifecycle or which are
     * not cluster global, but rather scoped to the PrivilegeConfiguration instance.
     */
    record DynamicDependencies(FlattenedActionGroups actionGroups, FlattenedActionGroups staticActionGroups, SecurityDynamicConfiguration<
        RoleV7> rolesConfiguration, ConfigV7 generalConfiguration, SpecialIndices specialIndices, Supplier<
            TenantPrivileges> tenantPrivilegesSupplier, Supplier<DashboardsMultiTenancyConfiguration> multiTenancyConfigurationSupplier,
        Map<String, SubjectBasedActionPrivileges.PrivilegeSpecification> pluginIdToPrivileges) {

        public static final DynamicDependencies EMPTY = new PrivilegesEvaluator.DynamicDependencies(
            FlattenedActionGroups.EMPTY,
            FlattenedActionGroups.EMPTY,
            SecurityDynamicConfiguration.empty(CType.ROLES),
            new ConfigV7(),
            new SpecialIndices(Settings.EMPTY),
            () -> TenantPrivileges.EMPTY,
            () -> DashboardsMultiTenancyConfiguration.DEFAULT,
            Map.of()
        );

        public DynamicDependencies with(SecurityDynamicConfiguration<RoleV7> roles) {
            return new DynamicDependencies(
                actionGroups,
                staticActionGroups,
                roles,
                generalConfiguration,
                specialIndices,
                tenantPrivilegesSupplier,
                multiTenancyConfigurationSupplier,
                pluginIdToPrivileges
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
                pluginIdToPrivileges
            );
        }

    }

    @FunctionalInterface
    interface Factory {
        PrivilegesEvaluator create(CoreDependencies coreDependencies, DynamicDependencies dynamicDependencies);
    }

}
