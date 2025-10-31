/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.rule.spi.AttributesExtension;

/**
 * Extension that provides {@link PrincipalAttribute} to the core autotagging-commons module
 */
public class PrincipalAttributesExtension implements AttributesExtension {

    public PrincipalAttributesExtension() {}

    @Override
    public Attribute getAttribute() {
        return PrincipalAttribute.PRINCIPAL;
    }
}
