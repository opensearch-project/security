package org.opensearch.security.dlic.rest.validation;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator;
import org.opensearch.security.dlic.rest.api.SecurityConfiguration;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import java.io.IOException;
import java.util.List;

import static java.util.function.Predicate.not;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.notFoundMessage;
import static org.opensearch.security.dlic.rest.support.Utils.withIOException;

public interface EndpointValidator {

    String resourceName();

    Endpoint endpoint();

    RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator();

    default boolean isCurrentUserAdmin() {
        return restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint());
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

    default ValidationResult<SecurityConfiguration> hasRightsToChangeEntity(final SecurityConfiguration securityConfiguration)
        throws IOException {
        final var immutableCheck = entityImmutable(securityConfiguration);
        if (!immutableCheck.isValid() && !isCurrentUserAdmin()) {
            return immutableCheck;
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> hasRightsToLoadOrChangeHiddenEntity(final SecurityConfiguration securityConfiguration) {
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
    ) {
        final var rolesToCheck = roles == null ? List.<String>of() : roles;
        return rolesToCheck.stream().map(role -> withIOException(() -> {
            final var roleSecConfig = SecurityConfiguration.of(role, rolesConfiguration);
            return entityExists("role", roleSecConfig).map(this::hasRightsToChangeEntity);
        }))
            .filter(not(ValidationResult::isValid))
            .findFirst()
            .<ValidationResult<SecurityDynamicConfiguration<?>>>map(
                result -> ValidationResult.error(result.status(), result.errorMessage())
            )
            .orElseGet(() -> ValidationResult.success(rolesConfiguration));
    }

    default ValidationResult<SecurityConfiguration> canChangeObjectWithRestAdminPermissions(
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        if (securityConfiguration.entityExists()) {
            final var configuration = securityConfiguration.configuration();
            final var existingActionGroup = configuration.getCEntry(securityConfiguration.entityName());
            if (restApiAdminPrivilegesEvaluator().containsRestApiAdminPermissions(existingActionGroup)) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }
        } else {
            final var configuration = securityConfiguration.configuration();
            final var reducedRequestContent = Utils.toConfigObject(
                securityConfiguration.requestContent(),
                configuration.getImplementingClass()
            );
            if (restApiAdminPrivilegesEvaluator().containsRestApiAdminPermissions(reducedRequestContent)) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }
        }
        return ValidationResult.success(securityConfiguration);
    }

    default ValidationResult<SecurityConfiguration> onConfigDelete(final SecurityConfiguration securityConfiguration) throws IOException {
        return hasRightsToChangeEntity(securityConfiguration).map(this::entityExists);
    }

    default ValidationResult<SecurityConfiguration> onConfigLoad(final SecurityConfiguration securityConfiguration) throws IOException {
        return hasRightsToLoadOrChangeHiddenEntity(securityConfiguration).map(this::entityExists);
    }

    default ValidationResult<SecurityConfiguration> onConfigChange(final SecurityConfiguration securityConfiguration) throws IOException {
        return hasRightsToChangeEntity(securityConfiguration);
    }

    RequestContentValidator createRequestContentValidator(final Object... params);

}
