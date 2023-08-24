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

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.MaskedField;
import org.opensearch.security.configuration.Salt;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesApiAction extends PatchableResourceApiAction {
    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/roles/"),
            new Route(Method.GET, "/roles/{name}"),
            new Route(Method.DELETE, "/roles/{name}"),
            new Route(Method.PUT, "/roles/{name}"),
            new Route(Method.PATCH, "/roles/"),
            new Route(Method.PATCH, "/roles/{name}")
        )
    );

    public static class RoleValidator extends RequestContentValidator {

        private static final Salt SALT = new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6 });

        protected RoleValidator(ValidationContext validationContext) {
            super(validationContext);
        }

        @Override
        public ValidationResult validate(RestRequest request) throws IOException {
            return super.validate(request).map(this::validateMaskedFields);
        }

        @Override
        public ValidationResult validate(RestRequest request, JsonNode jsonContent) throws IOException {
            return super.validate(request, jsonContent).map(this::validateMaskedFields);
        }

        private ValidationResult validateMaskedFields(final JsonNode content) {
            final ReadContext ctx = JsonPath.parse(content.toString());
            final List<String> maskedFields = ctx.read("$..masked_fields[*]");
            if (maskedFields != null) {
                for (String mf : maskedFields) {
                    if (!validateMaskedFieldSyntax(mf)) {
                        this.validationError = ValidationError.WRONG_DATATYPE;
                        return ValidationResult.error(this);
                    }
                }
            }
            return ValidationResult.success(content);
        }

        private boolean validateMaskedFieldSyntax(String mf) {
            try {
                new MaskedField(mf, SALT).isValid();
            } catch (Exception e) {
                wrongDataTypes.put("Masked field not valid: " + mf, e.getMessage());
                return false;
            }
            return true;
        }

    }

    @Inject
    public RolesApiAction(
        Settings settings,
        final Path configPath,
        RestController controller,
        Client client,
        AdminDNs adminDNs,
        ConfigurationRepository cl,
        ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ROLES;
    }

    @Override
    protected RequestContentValidator createValidator(final Object... params) {
        return new RoleValidator(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return params;
            }

            @Override
            public Settings settings() {
                return settings;
            }

            @Override
            public Map<String, DataType> allowedKeys() {
                final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                if (isSuperAdmin()) allowedKeys.put("reserved", DataType.BOOLEAN);
                return allowedKeys.put("cluster_permissions", DataType.ARRAY)
                    .put("tenant_permissions", DataType.ARRAY)
                    .put("index_permissions", DataType.ARRAY)
                    .put("description", DataType.STRING)
                    .build();
            }
        });
    }

    @Override
    protected String getResourceName() {
        return "role";
    }

    @Override
    protected CType getConfigName() {
        return CType.ROLES;
    }

    @Override
    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfiguration,
        final Object content,
        final String resourceName
    ) throws IOException {
        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(content)) {
            return isSuperAdmin();
        } else {
            return true;
        }
    }

    @Override
    protected boolean isReadOnly(SecurityDynamicConfiguration<?> existingConfiguration, String name) {
        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(existingConfiguration.getCEntry(name))) {
            return !isSuperAdmin();
        } else {
            return super.isReadOnly(existingConfiguration, name);
        }
    }

}
