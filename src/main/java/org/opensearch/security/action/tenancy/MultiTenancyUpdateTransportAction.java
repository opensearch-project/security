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

import java.io.IOException;
import java.util.Collections;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionListener;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.api.AbstractApiAction;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;


public class MultiTenancyUpdateTransportAction extends HandledTransportAction<BooleanSettingUpdateRequest, BooleanSettingRetrieveResponse> {

    private static final Logger log = LogManager.getLogger(MultiTenancyUpdateTransportAction.class);

    private final String securityIndex;
    private final ConfigurationRepository config;
    private final Client client;
    private final ThreadPool pool;

    @Inject
    public MultiTenancyUpdateTransportAction(final Settings settings,
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ConfigurationRepository config,
            final ThreadPool pool,
            final Client client) {
        super(MultiTenancyUpdateAction.NAME, transportService, actionFilters, BooleanSettingUpdateRequest::new);

        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);

        this.config = config;
        this.client = client;
        this.pool = pool;
    }

    /** Load the configuration from the security index and return a copy */
    protected final SecurityDynamicConfiguration<?> load() {
        return config.getConfigurationsFromIndex(Collections.singleton(CType.CONFIG), false).get(CType.CONFIG).deepClone();
    }
    
    @Override
    protected void doExecute(final Task task, final BooleanSettingUpdateRequest request, final ActionListener<BooleanSettingRetrieveResponse> listener) {

        // Get the current security config and prepare the config with the updated value 
        final SecurityDynamicConfiguration dynamicConfig = load();
        final ConfigV7 config = (ConfigV7)dynamicConfig.getCEntry("config");
        config.dynamic.kibana.multitenancy_enabled = request.getValue();
        dynamicConfig.putCEntry("config", config);

        // When performing an update to the configuration run as admin
        try (final ThreadContext.StoredContext stashedContext = pool.getThreadContext().stashContext()) {
            // Update the security configuration and make sure the cluster has fully refreshed
            AbstractApiAction.saveAndUpdateConfigs(this.securityIndex, this.client, CType.CONFIG, dynamicConfig, new ActionListener<IndexResponse>(){

                @Override
                public void onResponse(final IndexResponse response) {
                    // After processing the request, restore the user context
                    stashedContext.close();
                    try {
                        // Lookup the current value and notify the listener
                        client.execute(MultiTenancyRetrieveAction.INSTANCE, new EmptyRequest(), listener);
                    } catch (IOException ioe) {
                        log.error(ioe);
                        listener.onFailure(ioe);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    log.error(e);
                    listener.onFailure(e);
                }
            });
        }
    }
}
