/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard;

import java.util.ArrayList;
import java.util.Collection;

import org.elasticsearch.action.ActionModule;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.http.HttpServerModule;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestModule;
import org.elasticsearch.transport.TransportModule;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.auditlog.AuditLogModule;
import com.floragunn.searchguard.configuration.BackendModule;
import com.floragunn.searchguard.configuration.ConfigurationModule;
import com.floragunn.searchguard.configuration.SearchGuardIndexSearcherWrapperModule;
import com.floragunn.searchguard.filter.SearchGuardFilter;
import com.floragunn.searchguard.http.SearchGuardHttpServerTransport;
import com.floragunn.searchguard.rest.SearchGuardInfoAction;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ReflectionHelper;
import com.floragunn.searchguard.transport.SearchGuardTransportService;
import com.google.common.collect.ImmutableList;

public final class SearchGuardPlugin extends Plugin {

    private final ESLogger log = Loggers.getLogger(this.getClass());
    private static final String CLIENT_TYPE = "client.type";
    private final Settings settings;
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean tribeNodeClient;

    public SearchGuardPlugin(final Settings settings) {
        super();
        checkSSLPluginAvailable();
        if(!settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, true)) {
            throw new IllegalStateException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }
        this.settings = settings;
        client = !"node".equals(this.settings.get(CLIENT_TYPE, "node"));
        boolean tribeNode = this.settings.getAsBoolean("action.master.force_local", false) && this.settings.getByPrefix("tribe").getAsMap().size() > 0;
        tribeNodeClient = this.settings.get("tribe.name", null) != null;
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT);
        
        log.info("Node [{}] is a transportClient: {}/tribeNode: {}/tribeNodeClient: {}", settings.get("node.name"), client, tribeNode, tribeNodeClient);

        if(client && System.getProperty("sg.nowarn.client") == null) {
            System.out.println("*************************************************************************");
            System.out.println("'Search Guard 2' plugin is normally not needed on transport client nodes.");
            System.out.println("*************************************************************************");
        }
    }

    @Override
    public String name() {
        return "search-guard2";
    }

    @Override
    public String description() {
        return "Search Guard 2";
    }
    
    public Collection<Module> shardModules(Settings settings)
    {
      if (!client && !tribeNodeClient) {
        //TODO query caching 
        return ImmutableList.<Module>of(new SearchGuardIndexSearcherWrapperModule());
      }
      return ImmutableList.of();
    }

    @Override
    public Collection<Module> nodeModules() {
        final Collection<Module> modules = new ArrayList<>();
        if (!client && !tribeNodeClient) {
            modules.add(new ConfigurationModule());
            modules.add(new BackendModule());
            modules.add(new AuditLogModule());
        }
        return modules;
    }

    public void onModule(final ActionModule module) {
        
        if(!tribeNodeClient) {
            module.registerAction(ConfigUpdateAction.INSTANCE, TransportConfigUpdateAction.class);
            if (!client) {
                module.registerFilter(SearchGuardFilter.class);
            }
        }
    }

    @SuppressWarnings("unchecked")
	public void onModule(final RestModule module) {
        if (!client && !tribeNodeClient) {
            module.addRestAction(SearchGuardInfoAction.class);
            if(ReflectionHelper.canLoad("com.floragunn.dlic.rest.api.SearchGuardRestApiActions")) {
                try {
                	ReflectionHelper
                    .load("com.floragunn.dlic.rest.api.SearchGuardRestApiActions")
                    .getDeclaredMethod("addActions", RestModule.class)
                    .invoke(null, module);                	
                } catch(Exception ex) {
                	log.error("Failed to register SearchGuardRestApiActions, management API not available. Cause: {}", ex.getMessage());
                }
            }           
        }
    }

    public void onModule(final TransportModule module) {
        if (!client && !tribeNodeClient) {
            module.setTransportService(SearchGuardTransportService.class, name());
        }
    }
    
    public void onModule(final HttpServerModule module) {
        if (!client && httpSSLEnabled && !tribeNodeClient) {
            module.setHttpServerTransport(SearchGuardHttpServerTransport.class, name());
        }
    }

    @Override
    public Settings additionalSettings() {
        final Settings.Builder builder = Settings.settingsBuilder();
        return builder.build();
    }

    private void checkSSLPluginAvailable() {
        try {
            getClass().getClassLoader().loadClass("com.floragunn.searchguard.ssl.SearchGuardSSLPlugin");
        } catch (final ClassNotFoundException cnfe) {
            throw new IllegalStateException("SearchGuardSSLPlugin must be be installed");
        }
    }
}
