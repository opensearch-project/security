/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.dlic.rest.validation;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator;
import org.opensearch.security.dlic.rest.api.SecurityConfiguration;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.notFoundMessage;

public interface EndpointValidator {

    Endpoint endpoint();

    RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator();

    private String resourceName() {
        if (Objects.isNull(endpoint())) {
            return "";
        }
        switch (endpoint()) {
            case ACCOUNT:
                return "account";
            case ACTIONGROUPS:
                return "actiongroup";
            case ALLOWLIST:
            case AUDIT:
            case CONFIG:
                return "config";
            case INTERNALUSERS:
                return "user";
            case NODESDN:
                return "nodesdn";
            case ROLES:
                return "role";
            case ROLESMAPPING:
                return "rolesmapping";
            case TENANTS:
                return "tenant";
            default:
                return "";
        }
    }

    default boolean isCurrentUserAdmin() {
        return restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint());
    }

    default ValidationResult<String> withRequiredEntityName(final String entityName) {
        if (entityName == null) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("No " + resourceName() + " specified."));
        }
        return ValidationResult.success(entityName);
    }

    default ValidationResult<SecurityConfiguration> entityExists(final SecurityConfiguration securityConfiguration) {
        return entityExists(resourceName(), securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityExists(
        final String resourceName,
        final SecurityConfiguration securityConfiguration
    ) {
        return securityConfiguration.maybeEntityName().<ValidationResult<SecurityConfiguration>>map(entityName -> {
            if (!securityConfiguration.entityExists()) {
                return ValidationResult.error(
                    RestStatus.NOT_FOUND,
                    notFoundMessage(resourceName + " '" + securityConfiguration.entityName() + "' not found.")
                );
            }
            return ValidationResult.success(securityConfiguration);
        }).orElseGet(() -> ValidationResult.success(securityConfiguration));
    }

    default ValidationResult<SecurityConfiguration> isAllowedToChangeImmutableEntity(final SecurityConfiguration securityConfiguration)
        throws IOException {
        final var immutableCheck = entityImmutable(securityConfiguration);
        if (!immutableCheck.isValid() && !isCurrentUserAdmin()) {
            return immutableCheck;
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> isAllowedToLoadOrChangeHiddenEntity(final SecurityConfiguration securityConfiguration) {
        final var hiddenCheck = entityHidden(securityConfiguration);
        if (!hiddenCheck.isValid() && !isCurrentUserAdmin()) {
            return hiddenCheck;
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityImmutable(final SecurityConfiguration securityConfiguration) throws IOException {
        return entityHidden(securityConfiguration).map(this::entityStatic).map(this::entityReserved);
    }

    default ValidationResult<SecurityConfiguration> entityStatic(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        final var entityName = securityConfiguration.entityName();
        if (configuration.isStatic(entityName)) {

            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Resource '" + entityName + "' is static."));
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityReserved(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        final var entityName = securityConfiguration.entityName();
        if (configuration.isReserved(entityName)) {
            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Resource '" + entityName + "' is reserved."));
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> entityHidden(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        final var entityName = securityConfiguration.entityName();
        if (configuration.isHidden(entityName)) {

            return ValidationResult.error(RestStatus.NOT_FOUND, notFoundMessage("Resource '" + entityName + "' is not available."));
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityDynamicConfiguration<?>> validateRoles(
        final List<String> roles,
        final SecurityDynamicConfiguration<?> rolesConfiguration
    ) throws IOException {
        for (final var role : roles) {
            final var validRole = entityExists("role", SecurityConfiguration.of(role, rolesConfiguration)).map(
                this::isAllowedToLoadOrChangeHiddenEntity
            );
            if (!validRole.isValid()) {
                return ValidationResult.error(validRole.status(), validRole.errorMessage());
            }
        }
        return ValidationResult.success(rolesConfiguration);
    }

    default ValidationResult<SecurityConfiguration> isAllowedToChangeEntityWithRestAdminPermissions(
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        final var configuration = securityConfiguration.configuration();
        if (securityConfiguration.entityExists()) {
            final var existingEntity = configuration.getCEntry(securityConfiguration.entityName());
            if (restApiAdminPrivilegesEvaluator().containsRestApiAdminPermissions(existingEntity)) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }
        }
        if (securityConfiguration.requestContent() != null) {
            final var newConfigEntityContent = Utils.toConfigObject(
                securityConfiguration.requestContent(),
                configuration.getImplementingClass()
            );
            if (restApiAdminPrivilegesEvaluator().containsRestApiAdminPermissions(newConfigEntityContent)) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> onConfigDelete(final SecurityConfiguration securityConfiguration) throws IOException {
        return isAllowedToChangeImmutableEntity(securityConfiguration).map(this::entityExists);
    }

    default ValidationResult<SecurityConfiguration> onConfigLoad(final SecurityConfiguration securityConfiguration) throws IOException {
        return isAllowedToLoadOrChangeHiddenEntity(securityConfiguration).map(this::entityExists);
    }

    default ValidationResult<SecurityConfiguration> onConfigChange(final SecurityConfiguration securityConfiguration) throws IOException {
        return isAllowedToChangeImmutableEntity(securityConfiguration);
    }

    RequestContentValidator createRequestContentValidator(final Object... params);

}
