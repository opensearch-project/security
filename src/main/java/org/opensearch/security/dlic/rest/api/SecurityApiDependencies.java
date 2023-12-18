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

package org.opensearch.security.dlic.rest.api;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.support.ConfigConstants;

public class SecurityApiDependencies {
    private AdminDNs adminDNs;
    private final ConfigurationRepository configurationRepository;
    private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
    private final RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator;
    private final AuditLog auditLog;
    private final Settings settings;

    private final PrivilegesEvaluator privilegesEvaluator;

    public SecurityApiDependencies(
        final AdminDNs adminDNs,
        final ConfigurationRepository configurationRepository,
        final PrivilegesEvaluator privilegesEvaluator,
        final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator,
        final RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator,
        final AuditLog auditLog,
        final Settings settings
    ) {
        this.adminDNs = adminDNs;
        this.configurationRepository = configurationRepository;
        this.privilegesEvaluator = privilegesEvaluator;
        this.restApiPrivilegesEvaluator = restApiPrivilegesEvaluator;
        this.restApiAdminPrivilegesEvaluator = restApiAdminPrivilegesEvaluator;
        this.auditLog = auditLog;
        this.settings = settings;
    }

    public AdminDNs adminDNs() {
        return adminDNs;
    }

    public PrivilegesEvaluator privilegesEvaluator() {
        return privilegesEvaluator;
    }

    public ConfigurationRepository configurationRepository() {
        return configurationRepository;
    }

    public RestApiPrivilegesEvaluator restApiPrivilegesEvaluator() {
        return restApiPrivilegesEvaluator;
    }

    public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
        return restApiAdminPrivilegesEvaluator;
    }

    public AuditLog auditLog() {
        return auditLog;
    }

    public Settings settings() {
        return settings;
    }

    public String securityIndexName() {
        return settings().get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
    }
}
