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
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.elasticsearch.action.ActionModule;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;

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
import com.floragunn.searchguard.transport.SearchGuardTransportService;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

public final class SearchGuardPlugin extends Plugin {

    private static final String CLIENT_TYPE = "client.type";
    private final Settings settings;
    private final boolean client;
    private final boolean httpSSLEnabled;
    //private boolean tribe; // TODO check tribe node

    public SearchGuardPlugin(final Settings settings) {
        super();
        checkSSLPluginAvailable();
        if(!settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, true)) {
            throw new IllegalStateException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }
        this.settings = settings;
        client = !"node".equals(this.settings.get(CLIENT_TYPE, "node"));
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT);
        
        if(client && System.getProperty("sg.nowarn.client") ==  null) {
            System.out.println("*************************************************************");
            System.out.println("'Search Guard 2' plugin must not be installed on client nodes.");
            System.out.println("'Search Guard SSL' plugin is enough");
            System.out.println("*************************************************************");
        }
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
            modules.add(new AuditLogModule());
        }
        return modules;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Collection<Class<? extends LifecycleComponent>> nodeServices() {
        final Collection<Class<? extends LifecycleComponent>> services = new ArrayList<>();
        if (!client) {
            //services.add(ConfigurationService.class);
        }
        return services;
    }

    /*public void onModule(final ActionModule module) {
        module.registerAction(ConfigUpdateAction.INSTANCE, TransportConfigUpdateAction.class);
        if (!client) {            
            module.registerFilter(SearchGuardFilter.class);
        }
    }*/
    
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        settings.add(Setting.listSetting("searchguard.authcz.admin_dn", Collections.emptyList(), Function.identity(), Property.NodeScope));
        settings.add(Setting.listSetting("searchguard.authcz.impersonation_dn", Collections.emptyList(), Function.identity(), Property.NodeScope));

        settings.add(Setting.simpleString("searchguard.audit.type", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.index", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.type", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.username", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.audit.config.password", Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.simpleString("searchguard.kerberos.krb5_filepath", Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString("searchguard.kerberos.acceptor_keytab_filepath", Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.listSetting("searchguard.audit.config.http_endpoints", Lists.newArrayList("localhost:9200"), Function.identity(), Property.NodeScope));
 
        settings.add(Setting.boolSetting("searchguard.audit.config.enable_ssl", false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.config.verify_hostnames", true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting("searchguard.audit.config.enable_ssl_client_auth", false, Property.NodeScope, Property.Filtered));
        
        
                
        return settings;
    }

    public void onModule(final NetworkModule module) {
    	
        if (!client) {
            module.registerRestHandler(SearchGuardInfoAction.class);
            module.registerTransportService(SearchGuardTransportService.class.toString(), SearchGuardTransportService.class);
        }
    	
        if (!client && httpSSLEnabled) {
            module.registerHttpTransport(SearchGuardHttpServerTransport.class.toString(), SearchGuardHttpServerTransport.class);
        }
    	
    }    
        
    @Override
    public Settings additionalSettings() {
        final Settings.Builder builder = Settings.builder();

        if (!client && httpSSLEnabled) {
            builder.put(NetworkModule.HTTP_TYPE_KEY, SearchGuardHttpServerTransport.class.toString());
        }

        if (!client) {
            builder.put(NetworkModule.TRANSPORT_SERVICE_TYPE_KEY, SearchGuardTransportService.class.toString());
        }

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
