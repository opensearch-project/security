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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.PrivilegesInterceptorImpl;
import org.opensearch.security.privileges.actionlevel.RuntimeOptimizedActionPrivileges;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

/**
 * This class manages and gives access to various additional classes which are derived from privileges related configuration in
 * the security plugin.
 * <p>
 *     This is especially:
 * <ul>
 *     <li>The current PrivilegesEvaluator instance</li>
 *     <li>The current Dashboards multi tenancy configuration</li>
 *     <li>The current action groups configuration</li>
 * </ul>
 * This class also manages updates to the different configuration objects.
 * <p>
 * Historically, most of this information has been located directly in PrivilegesEvaluator instances. To concentrate
 * the purpose of PrivilegesEvaluator to just action based privilege evaluation, the information was distributed amongst
 * several classes.
 */
public class PrivilegesConfiguration {
    private final static Logger log = LogManager.getLogger(PrivilegesConfiguration.class);

    private final AtomicReference<TenantPrivileges> tenantPrivileges = new AtomicReference<>(TenantPrivileges.EMPTY);
    private final AtomicReference<PrivilegesEvaluator> privilegesEvaluator;
    private final AtomicReference<FlattenedActionGroups> actionGroups = new AtomicReference<>(FlattenedActionGroups.EMPTY);
    private final Map<String, RoleV7> pluginIdToRolePrivileges = new HashMap<>();
    private final AtomicReference<DashboardsMultiTenancyConfiguration> multiTenancyConfiguration = new AtomicReference<>(
        DashboardsMultiTenancyConfiguration.DEFAULT
    );
    private final PrivilegesInterceptorImpl privilegesInterceptor;
    private final SpecialIndices specialIndices;

    /**
     * The pure static action groups should be ONLY used by action privileges for plugins; only those cannot and should
     * not have knowledge of any action groups defined in the dynamic configuration. All other functionality should
     * use the action groups derived from the dynamic configuration (which is always computed on the fly on
     * configuration updates).
     */
    private final FlattenedActionGroups staticActionGroups;

    public PrivilegesConfiguration(
        ConfigurationRepository configurationRepository,
        ClusterService clusterService,
        Supplier<ClusterState> clusterStateSupplier,
        Client client,
        RoleMapper roleMapper,
        ThreadPool threadPool,
        IndexNameExpressionResolver resolver,
        AuditLog auditLog,
        Settings settings,
        Supplier<String> unavailablityReasonSupplier
    ) {

        this.privilegesEvaluator = new AtomicReference<>(new PrivilegesEvaluator.NotInitialized(unavailablityReasonSupplier));
        this.privilegesInterceptor = new PrivilegesInterceptorImpl(
            resolver,
            clusterService,
            client,
            threadPool,
            this.tenantPrivileges::get,
            this.multiTenancyConfiguration::get
        );
        this.staticActionGroups = buildStaticActionGroups();
        this.specialIndices = new SpecialIndices(settings);

        if (configurationRepository != null) {
            configurationRepository.subscribeOnChange(configMap -> {
                SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfiguration = configurationRepository.getConfiguration(
                    CType.ACTIONGROUPS
                );
                SecurityDynamicConfiguration<RoleV7> rolesConfiguration = configurationRepository.getConfiguration(CType.ROLES)
                    .withStaticConfig();
                SecurityDynamicConfiguration<TenantV7> tenantConfiguration = configurationRepository.getConfiguration(CType.TENANTS)
                    .withStaticConfig();
                ConfigV7 generalConfiguration = configurationRepository.getConfiguration(CType.CONFIG).getCEntry(CType.CONFIG.name());

                FlattenedActionGroups flattenedActionGroups = new FlattenedActionGroups(actionGroupsConfiguration.withStaticConfig());
                this.actionGroups.set(flattenedActionGroups);

                PrivilegesEvaluator currentPrivilegesEvaluator = privilegesEvaluator.get();
                PrivilegesEvaluationType privilegesEvaluationType = PrivilegesEvaluationType.getFrom(
                    configurationRepository.getConfiguration(CType.CONFIG)
                );
                PrivilegesEvaluationType currentEvaluationType = PrivilegesEvaluationType.typeOf(currentPrivilegesEvaluator);

                if (privilegesEvaluationType != currentEvaluationType) {
                    if (privilegesEvaluationType == PrivilegesEvaluationType.LEGACY) {
                        PrivilegesEvaluator oldInstance = privilegesEvaluator.getAndSet(
                            new org.opensearch.security.privileges.actionlevel.legacy.PrivilegesEvaluator(
                                clusterService,
                                clusterStateSupplier,
                                roleMapper,
                                threadPool,
                                threadPool.getThreadContext(),
                                resolver,
                                auditLog,
                                settings,
                                privilegesInterceptor,
                                flattenedActionGroups,
                                staticActionGroups,
                                rolesConfiguration,
                                generalConfiguration,
                                pluginIdToRolePrivileges
                            )
                        );
                        if (oldInstance != null) {
                            oldInstance.shutdown();
                        }
                    } else {
                        PrivilegesEvaluator oldInstance = privilegesEvaluator.getAndSet(
                            new org.opensearch.security.privileges.actionlevel.nextgen.PrivilegesEvaluator(
                                clusterStateSupplier,
                                roleMapper,
                                threadPool,
                                threadPool.getThreadContext(),
                                resolver,
                                settings,
                                privilegesInterceptor,
                                flattenedActionGroups,
                                staticActionGroups,
                                rolesConfiguration,
                                generalConfiguration,
                                pluginIdToRolePrivileges,
                                new RuntimeOptimizedActionPrivileges.SpecialIndexProtection(
                                    this.specialIndices::isUniversallyDeniedIndex,
                                    this.specialIndices::isSystemIndex
                                )
                            )
                        );
                        if (oldInstance != null) {
                            oldInstance.shutdown();
                        }
                    }
                } else {
                    privilegesEvaluator.get().updateConfiguration(flattenedActionGroups, rolesConfiguration, generalConfiguration);
                }

                try {
                    this.multiTenancyConfiguration.set(new DashboardsMultiTenancyConfiguration(generalConfiguration));
                } catch (Exception e) {
                    log.error("Error while updating DashboardsMultiTenancyConfiguration", e);
                }

                try {
                    this.tenantPrivileges.set(new TenantPrivileges(rolesConfiguration, tenantConfiguration, flattenedActionGroups));
                } catch (Exception e) {
                    log.error("Error while updating TenantPrivileges", e);
                }
            });
        }

        if (clusterService != null) {
            clusterService.addListener(event -> { this.privilegesEvaluator.get().updateClusterStateMetadata(clusterService); });
        }
    }

    /**
     * For testing only: Creates a passive PrivilegesConfiguration object with the given PrivilegesEvaluator implementation and otherwise
     * just defaults.
     */
    public PrivilegesConfiguration(PrivilegesEvaluator privilegesEvaluator) {
        this.privilegesEvaluator = new AtomicReference<>(privilegesEvaluator);
        this.privilegesInterceptor = null;
        this.staticActionGroups = buildStaticActionGroups();
        this.specialIndices = new SpecialIndices(Settings.EMPTY);
    }

    /**
     * Returns the current tenant privileges object. Important: Do not store the references to the instances returned here; these will change
     * after configuration updates.
     */
    public TenantPrivileges tenantPrivileges() {
        return this.tenantPrivileges.get();
    }

    /**
     * Returns the current PrivilegesEvaluator implementation. Important: Do not store the references to the instances returned here; these will change
     * after configuration updates.
     */
    public PrivilegesEvaluator privilegesEvaluator() {
        return this.privilegesEvaluator.get();
    }

    /**
     * Returns the current action groups configuration. Important: Do not store the references to the instances returned here; these will change
     * after configuration updates.
     */
    public FlattenedActionGroups actionGroups() {
        return this.actionGroups.get();
    }

    /**
     * Returns the current Dashboards multi tenancy configuration. Important: Do not store the references to the instances returned here; these will change
     * after configuration updates.
     */
    public DashboardsMultiTenancyConfiguration multiTenancyConfiguration() {
        return this.multiTenancyConfiguration.get();
    }

    public void updatePluginToActionPrivileges(String pluginIdentifier, RoleV7 pluginPermissions) {
        pluginIdToRolePrivileges.put(pluginIdentifier, pluginPermissions);
    }

    public boolean isInitialized() {
        return this.privilegesEvaluator().isInitialized();
    }

    /**
     * TODO: Think about better names
     */
    enum PrivilegesEvaluationType {
        LEGACY,
        NEXT_GEN;

        static PrivilegesEvaluationType getFrom(SecurityDynamicConfiguration<ConfigV7> configConfig) {
            final PrivilegesEvaluationType defaultValue = PrivilegesEvaluationType.LEGACY;

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

        static PrivilegesEvaluationType typeOf(PrivilegesEvaluator privilegesEvaluator) {
            if (privilegesEvaluator instanceof org.opensearch.security.privileges.actionlevel.legacy.PrivilegesEvaluator) {
                return PrivilegesEvaluationType.LEGACY;
            } else if (privilegesEvaluator instanceof org.opensearch.security.privileges.actionlevel.nextgen.PrivilegesEvaluator) {
                return PrivilegesEvaluationType.NEXT_GEN;
            } else {
                return null;
            }
        }
    }

    private static FlattenedActionGroups buildStaticActionGroups() {
        return new FlattenedActionGroups(DynamicConfigFactory.addStatics(SecurityDynamicConfiguration.empty(CType.ACTIONGROUPS)));
    }

}
