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

import java.util.Collection;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtMethod;
import javassist.CtNewMethod;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionModule;
import org.elasticsearch.common.collect.ImmutableList;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.lang3.StringUtils;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.rest.RestModule;

import com.floragunn.searchguard.filter.DLSActionFilter;
import com.floragunn.searchguard.filter.FLSActionFilter;
import com.floragunn.searchguard.filter.RequestActionFilter;
import com.floragunn.searchguard.filter.SearchGuardActionFilter;
import com.floragunn.searchguard.http.netty.SSLNettyHttpServerTransport;
import com.floragunn.searchguard.rest.SearchGuardInfoAction;
import com.floragunn.searchguard.service.SearchGuardConfigService;
import com.floragunn.searchguard.service.SearchGuardService;
import com.floragunn.searchguard.transport.SSLClientNettyTransport;
import com.floragunn.searchguard.transport.SSLNettyTransport;
import com.floragunn.searchguard.transport.SearchGuardNettyTransport;
import com.floragunn.searchguard.util.ConfigConstants;

//TODO FUTURE store users/roles also in elasticsearch search guard index
//TODO FUTURE Multi authenticator/authorizator
//TODO FUTURE special handling scroll searches
//TODO FUTURE negative rules/users in acrules
//TODO update some settings during runtime
public final class SearchGuardPlugin extends AbstractPlugin {

    @Override
    public void processModule(final Module module) {
        super.processModule(module);
    }

    private static final String SEARCHGUARD_DEBUG = "searchguard.debug";
    private static final String CLIENT_TYPE = "client.type";
    private static final String HTTP_TYPE = "http.type";
    private static final String TRANSPORT_TYPE = "transport.type";
    private static final String BULK_UDP_ENABLED = "bulk.udp.enabled";

    private static final ESLogger log = Loggers.getLogger(SearchGuardPlugin.class);
    private final boolean enabled;
    private final boolean client;
    private final Settings settings;
    public static final boolean DLS_SUPPORTED;

    //TODO make non static and check "enabled"
    static {

        if (Boolean.parseBoolean(System.getProperty(SearchGuardPlugin.SEARCHGUARD_DEBUG, "false"))) {
            System.setProperty("javax.net.debug", "all");
            System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.debug", "all");
        }

        boolean dlsSupported = false;

        try {
            final ClassPool pool = ClassPool.getDefault();
            final CtClass cc = pool.get("org.elasticsearch.search.SearchService");
            final CtField f = CtField.make("private com.floragunn.searchguard.filter.level.SearchContextCallback callback = null;", cc);
            cc.addField(f);

            final CtMethod m = CtNewMethod
                    .make("public void setCallback(com.floragunn.searchguard.filter.level.SearchContextCallback callback){this.callback = callback;}",
                            cc);
            cc.addMethod(m);

            final CtMethod me = cc.getDeclaredMethod("createContext");
            me.insertAt(574, "if(callback != null) {callback.onCreateContext(context, request);}");

            cc.toClass();
            log.info("Class enhancements for DLS/FLS successful");
            dlsSupported = true;
        } catch (final Exception e) {
            log.error("Class enhancements for DLS/FLS not successful due to {}", e, e.toString());
        }

        DLS_SUPPORTED = dlsSupported;
    }

    public SearchGuardPlugin(final Settings settings) {

        this.settings = settings;
        enabled = this.settings.getAsBoolean(ConfigConstants.SEARCHGUARD_ENABLED, true);
        client = !"node".equals(this.settings.get(SearchGuardPlugin.CLIENT_TYPE, "node"));
    }

    public void onModule(final RestModule module) {
        if (enabled && !client) {
            module.addRestAction(SearchGuardInfoAction.class);
        }

    }

    public void onModule(final ActionModule module) {
        if (enabled && !client) {
            module.registerFilter(SearchGuardActionFilter.class);
            module.registerFilter(RequestActionFilter.class);
            module.registerFilter(DLSActionFilter.class);
            module.registerFilter(FLSActionFilter.class);
        }
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Collection<Class<? extends LifecycleComponent>> services() {

        if (enabled && !client) {
            return ImmutableList.<Class<? extends LifecycleComponent>> of(SearchGuardService.class, SearchGuardConfigService.class);
        }
        return ImmutableList.of();
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Collection<Class<? extends Module>> modules() {
        if (enabled && !client) {
            return ImmutableList.<Class<? extends Module>> of(AuthModule.class);
        }
        return ImmutableList.of();
    }

    @Override
    public Settings additionalSettings() {
        if (enabled) {
            checkSSLConfig();
            final org.elasticsearch.common.settings.ImmutableSettings.Builder builder = ImmutableSettings.settingsBuilder();
            if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENABLED, false)) {
                builder.put(SearchGuardPlugin.TRANSPORT_TYPE, client ? SSLClientNettyTransport.class : SSLNettyTransport.class);
            } else if (!client) {
                builder.put(SearchGuardPlugin.TRANSPORT_TYPE, SearchGuardNettyTransport.class);
            }

            if (!client) {
                if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_ENABLED, false)) {
                    builder.put(SearchGuardPlugin.HTTP_TYPE, SSLNettyHttpServerTransport.class);
                }

                if (settings.getAsBoolean(SearchGuardPlugin.BULK_UDP_ENABLED, false)) {
                    log.error("UDP Bulk service enabled, will disable it because its unsafe and deprecated");
                }

                builder.put(SearchGuardPlugin.BULK_UDP_ENABLED, false);
            }

            return builder.build();
        } else {
            return ImmutableSettings.Builder.EMPTY_SETTINGS;
        }
    }

    private void checkSSLConfig() {
        if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENABLED, false)) {
            final String keystoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.keyStore", null));
            final String truststoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.trustStore", null));

            if (StringUtils.isBlank(keystoreFilePath) || StringUtils.isBlank(truststoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH + " and "
                        + ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH + " must be set if transport ssl is reqested.");
            }
        }

        if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_ENABLED, false)) {
            final String keystoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.keyStore", null));
            final String truststoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.trustStore", null));

            if (StringUtils.isBlank(keystoreFilePath) || StringUtils.isBlank(truststoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH + " and "
                        + ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH + " must be set if https is reqested.");
            }
        }

    }

    @Override
    public String description() {
        return "Search Guard" + (enabled ? "" : " (disabled)");
    }

    @Override
    public String name() {
        return "searchguard" + (enabled ? "" : " (disabled)");
    }

}
