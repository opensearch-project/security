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

import java.util.Collections;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class MultiTenancyRetrieveTransportAction
        extends HandledTransportAction<EmptyRequest, BooleanSettingRetrieveResponse> {

    private final ConfigurationRepository config;

    @Inject
    public MultiTenancyRetrieveTransportAction(final Settings settings,
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ConfigurationRepository config) {
        super(MultiTenancyRetrieveAction.NAME, transportService, actionFilters, EmptyRequest::new);

        this.config = config;
    }

    /** Load the configuration from the security index and return a copy */
    protected final SecurityDynamicConfiguration<?> load() {
        return config.getConfigurationsFromIndex(Collections.singleton(CType.CONFIG), false).get(CType.CONFIG).deepClone();
    }
    
    @Override
    protected void doExecute(final Task task, final EmptyRequest request, final ActionListener<BooleanSettingRetrieveResponse> listener) {
        // Get the security configuration and lookup the config setting state
        final SecurityDynamicConfiguration<?> dynamicConfig = load();
        ConfigV7 config = (ConfigV7)dynamicConfig.getCEntry("config");
        final Boolean value = config.dynamic.kibana.multitenancy_enabled;
       
        listener.onResponse(new BooleanSettingRetrieveResponse(value));
    }
}
