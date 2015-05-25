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

package com.floragunn.searchguard.service;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FileUtils;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.search.SearchService;

import com.floragunn.searchguard.audit.AuditListener;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.http.HTTPAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.filter.level.ConfigurableSearchContextCallback;
import com.floragunn.searchguard.filter.level.SearchContextCallback;
import com.floragunn.searchguard.http.SessionStore;
import com.floragunn.searchguard.rest.DefaultRestFilter;
import com.floragunn.searchguard.rest.RestActionFilter;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class SearchGuardService extends AbstractLifecycleComponent<SearchGuardService> {

    //private final String securityConfigurationIndex;
    private final RestController restController;
    private final Client client;
    private final Settings settings;
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private Method method;
    private Method searchServiceSetCallbackMethod;
    private final AuditListener auditListener;
    private static SecretKey secretKey;

    private final Authorizator authorizator;

    private final AuthenticationBackend authenticationBackend;

    private final HTTPAuthenticator httpAuthenticator;

    private final SessionStore sessionStore;

    public Authorizator getAuthorizator() {
        return authorizator;
    }

    public AuthenticationBackend getAuthenticationBackend() {
        return authenticationBackend;
    }

    public HTTPAuthenticator getHttpAuthenticator() {
        return httpAuthenticator;
    }

    public RestController getRestController() {
        return restController;
    }

    public RestHandler getHandler(final RestRequest request) throws IllegalAccessException, IllegalArgumentException,
            InvocationTargetException, NoSuchMethodException, SecurityException {
        return (RestHandler) method.invoke(restController, request);
    }

    @Inject
    public SearchGuardService(final Settings settings, final RestController restController, final Client client,
            final Authorizator authorizator, final AuthenticationBackend authenticationBackend, final HTTPAuthenticator httpAuthenticator,
            final SessionStore sessionStore, final AuditListener auditListener, final SearchService searchService) {
        super(settings);
        this.restController = restController;
        this.client = client;
        this.settings = settings;
        //securityConfigurationIndex = settings
        //        .get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX);
        this.authenticationBackend = authenticationBackend;
        this.authorizator = authorizator;
        this.httpAuthenticator = httpAuthenticator;
        this.sessionStore = sessionStore;

        try {
            method = RestController.class.getDeclaredMethod("getHandler", RestRequest.class);
            method.setAccessible(true);
        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new ElasticsearchException(e.toString());
        }

        try {
            searchServiceSetCallbackMethod = SearchService.class.getDeclaredMethod("setCallback", SearchContextCallback.class);
            searchServiceSetCallbackMethod.invoke(searchService, new ConfigurableSearchContextCallback(settings, auditListener));
        } catch (final Exception e) {
            log.error(e.toString(), e);
            //throw new ElasticsearchException(e.toString());
        }

        this.auditListener = auditListener;
        //TODO FUTURE index change audit trail

        final String keyPath = settings.get(ConfigConstants.SEARCHGUARD_KEY_PATH, ".");
        SecretKey sc = null;
        try {

            final File keyFile = new File(keyPath, "searchguard_node_key.key");

            if (keyFile.exists()) {
                log.debug("Loaded key from {}", keyFile.getAbsolutePath());
                sc = new SecretKeySpec(FileUtils.readFileToByteArray(keyFile), "AES");
            } else {

                final SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
                final KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128, secRandom);
                final SecretKey secretKey = kg.generateKey();
                final byte[] enckey = secretKey.getEncoded();

                if (enckey == null || enckey.length != 16) {
                    throw new Exception("invalid key " + (enckey == null ? -1 : enckey.length));
                }
                FileUtils.writeByteArrayToFile(keyFile, enckey);
                sc = secretKey;
                log.info("New key written to {}, make sure all nodes have this key", keyFile.getAbsolutePath());
            }

        } catch (final Exception e) {
            log.error("Cannot generate or read secrety key", e);
            throw new ElasticsearchException(e.toString());
        }

        final boolean checkForRoot = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_CHECK_FOR_ROOT, true);

        if (SecurityUtil.isRootUser()) {

            if (checkForRoot) {
                throw new ElasticsearchException("You're trying to run elasticsearch as root or Windows Administrator and thats forbidden.");
            } else {
                log.warn("You're trying to run elasticsearch as root or Windows Administrator! Thats a potential security issue.");
            }

        }

        final String scriptingStatus = settings.get(ScriptService.DISABLE_DYNAMIC_SCRIPTING_SETTING,
                ScriptService.DISABLE_DYNAMIC_SCRIPTING_DEFAULT);

        if (scriptingStatus.equalsIgnoreCase(ScriptService.DISABLE_DYNAMIC_SCRIPTING_DEFAULT)) {
            log.warn("{} has the default value {}, consider setting it to false if not needed",
                    ScriptService.DISABLE_DYNAMIC_SCRIPTING_SETTING, scriptingStatus);
        }

        if (scriptingStatus.equalsIgnoreCase("true")) {
            log.error("{} is configured insecure, consider setting it to false or " + ScriptService.DISABLE_DYNAMIC_SCRIPTING_DEFAULT,
                    ScriptService.DISABLE_DYNAMIC_SCRIPTING_SETTING);
        }

        if (searchService == null) {
            throw new RuntimeException("ssnull");
        }

        SearchGuardService.secretKey = sc;
    }

    public static SecretKey getSecretKey() {
        return secretKey;
    }

    public SessionStore getSessionStore() {
        return sessionStore;
    }

    public Settings getSettings() {
        return settings;
    }

    public Client getClient() {
        return client;
    }

    @Override
    protected void doStart() throws ElasticsearchException {

        restController.registerFilter(new DefaultRestFilter(this, null, null, auditListener));

        final String[] restActionFilters = settings.getAsArray(ConfigConstants.SEARCHGUARD_RESTACTIONFILTER);
        for (int i = 0; i < restActionFilters.length; i++) {
            final String filterName = restActionFilters[i];
            restController.registerFilter(new RestActionFilter(this, "restactionfilter", filterName, auditListener));
            //filterRegistered = true;
        }

        //TODO FUTURE version compatibility
        /* if(!Version.CURRENT.before(Version.V_1_4_2)) {
             throw new ElasticsearchException("Wrong ES version, use 1.4.2 or later");
         }*/

        /*if (!filterRegistered) {
            throw new ElasticsearchException("No filter configured");
        }*/

        // log.info("Starting Search Guard with {} filters",
        //         (restActionFilters.length + dlsFilters.length + flsFilters.length + arFilters.length));

        log.trace("With settings " + this.settings.getAsMap());

    }

    /*public String getSecurityConfigurationIndex() {
        return securityConfigurationIndex;
    }*/

    @Override
    protected void doStop() throws ElasticsearchException {
        //no-op

    }

    @Override
    protected void doClose() throws ElasticsearchException {
        //no-op

    }
}
