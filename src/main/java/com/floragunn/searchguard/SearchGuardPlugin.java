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
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestModule;
import org.elasticsearch.transport.TransportModule;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.configuration.BackendModule;
import com.floragunn.searchguard.configuration.ConfigurationModule;
import com.floragunn.searchguard.configuration.ConfigurationService;
import com.floragunn.searchguard.configuration.SearchGuardIndexSearcherWrapperModule;
import com.floragunn.searchguard.filter.SearchGuardFilter;
import com.floragunn.searchguard.rest.SearchGuardInfoAction;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.transport.SearchGuardTransportService;
import com.google.common.collect.ImmutableList;

public final class SearchGuardPlugin extends Plugin {

    private static final String CLIENT_TYPE = "client.type";
    private final Settings settings;
    private final boolean client;
    //private boolean tribe; // TODO check tribe node

    public SearchGuardPlugin(final Settings settings) {
        super();
        System.out.println("************************************************");
        System.out.println("This is alpha software, do not use in production");
        System.out.println("************************************************");
        checkSSLPluginAvailable();
        if(!settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, true)) {
            throw new IllegalStateException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }
        this.settings = settings;
        client = !"node".equals(this.settings.get(CLIENT_TYPE, "node"));
        
        if(client) {
            System.out.println("*************************************************************");
            System.out.println("'Search Guard 2' plugin must not be installed on client nodes.");
            System.out.println("'Search Guard SSL' plugin is enough");
            System.out.println("*************************************************************");
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
      if (!client) {
        //TODO query caching 
        return ImmutableList.<Module>of(new SearchGuardIndexSearcherWrapperModule());
      }
      return ImmutableList.of();
    }

    @Override
    public Collection<Module> nodeModules() {
        final Collection<Module> modules = new ArrayList<>();
        if (!client) {
            modules.add(new ConfigurationModule());
            modules.add(new BackendModule());
        }
        return modules;
    }

    @Override
    public Collection<Class<? extends LifecycleComponent>> nodeServices() {
        final Collection<Class<? extends LifecycleComponent>> services = new ArrayList<>();
        if (!client) {
            services.add(ConfigurationService.class);
        }
        return services;
    }

    public void onModule(final ActionModule module) {
        if (!client) {
            module.registerAction(ConfigUpdateAction.INSTANCE, TransportConfigUpdateAction.class);
            module.registerFilter(SearchGuardFilter.class);
        }
    }

    public void onModule(final RestModule module) {
        if (!client) {
            module.addRestAction(SearchGuardInfoAction.class);
        }
    }

    public void onModule(final TransportModule module) {
        if (!client) {
            module.setTransportService(SearchGuardTransportService.class, name());
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
