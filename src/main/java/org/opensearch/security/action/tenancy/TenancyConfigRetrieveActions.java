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

package org.opensearch.security.action.tenancy;

import org.opensearch.action.ActionType;

public class TenancyConfigRetrieveActions extends ActionType<TenancyConfigRetrieveResponse> {

    public static final TenancyConfigRetrieveActions INSTANCE = new TenancyConfigRetrieveActions();
    public static final String NAME = "cluster:feature/tenancy/config/read";

    protected TenancyConfigRetrieveActions() {
        super(NAME, TenancyConfigRetrieveResponse::new);
    }
}
