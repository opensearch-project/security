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
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.util.FakeRestRequest;

import tools.jackson.databind.InjectableValues;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuditApiActionRequestContentValidatorTest extends AbstractApiActionValidationTest {
    private RequestContentValidator validator;

    @Before
    public void setupAuditValidator() {
        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, Settings.EMPTY);
        DefaultObjectMapper.inject(injectableValues);
        validator = new AuditApiAction(clusterService, threadPool, securityApiDependencies).createEndpointValidator()
            .createRequestContentValidator();
    }

    @Test
    public void acceptsEveryDefinedCategory() throws IOException {
        for (var category : AuditCategory.values()) {
            assertCategoryValidation(category.name(), true);
        }
    }

    @Test
    public void rejectsUnknownCategories() throws IOException {
        assertCategoryValidation("UNKNOWN_CATEGORY", false);
    }

    @Test
    public void acceptsNoneAndCaseInsensitiveNames() throws IOException {
        assertCategoryValidation("NONE", true);
        assertCategoryValidation("failed_login", true);
    }

    private void assertCategoryValidation(String category, boolean valid) throws IOException {
        for (String field : List.of("disabled_categories", "disabled_rest_categories", "disabled_transport_categories")) {
            String content = "{\"audit\":{\"" + field + "\":[\"" + category + "\"]}}";
            var request = FakeRestRequest.builder().withContent(new BytesArray(content)).build();
            // Cover both raw PUT bodies and parsed PATCH payloads.
            for (var result : List.of(validator.validate(request), validator.validate(request, objectMapper.readTree(content)))) {
                if (valid) {
                    assertTrue(field + ": " + category, result.isValid());
                } else {
                    assertFalse(result.isValid());
                    assertThat(result.status(), is(RestStatus.BAD_REQUEST));
                }
            }
        }
    }
}
