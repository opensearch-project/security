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

import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.InjectableValues;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.util.FakeRestRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class AuditApiActionRequestContentValidatorTest extends AbstractApiActionValidationTest {

    @Test
    public void validateAuditDisabledRestCategories() throws IOException {
        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, Settings.EMPTY);
        DefaultObjectMapper.inject(injectableValues);
        final var auditApiActionRequestContentValidator = new AuditApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator()
            .createRequestContentValidator();

        final var disabledTransportCategories = AuditApiAction.AuditRequestContentValidator.DISABLED_TRANSPORT_CATEGORIES.stream()
            .map(Enum::name)
            .collect(Collectors.toList());
        final var auditConfig = new AuditConfig(
            true,
            AuditConfig.Filter.from(Map.of("disabled_rest_categories", disabledTransportCategories)),
            ComplianceConfig.DEFAULT
        );
        final var content = DefaultObjectMapper.writeValueAsString(objectMapper.valueToTree(auditConfig), false);
        var result = auditApiActionRequestContentValidator.validate(FakeRestRequest.builder().withContent(new BytesArray(content)).build());
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());
    }

    @Test
    public void validateAuditDisabledTransportCategories() throws IOException {
        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, Settings.EMPTY);
        DefaultObjectMapper.inject(injectableValues);
        final var auditApiActionRequestContentValidator = new AuditApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator()
            .createRequestContentValidator();

        final var disabledRestCategories = Stream.of(AuditCategory.COMPLIANCE_DOC_WRITE, AuditCategory.COMPLIANCE_DOC_READ)
            .map(Enum::name)
            .collect(Collectors.toList());
        final var auditConfig = new AuditConfig(
            true,
            AuditConfig.Filter.from(Map.of("disabled_transport_categories", disabledRestCategories)),
            ComplianceConfig.DEFAULT
        );
        final var content = DefaultObjectMapper.writeValueAsString(objectMapper.valueToTree(auditConfig), false);
        var result = auditApiActionRequestContentValidator.validate(FakeRestRequest.builder().withContent(new BytesArray(content)).build());
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());
    }
}
