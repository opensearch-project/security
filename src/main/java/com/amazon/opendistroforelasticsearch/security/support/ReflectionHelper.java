/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.support;

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.NullAuditLog;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceIndexingOperationListener;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.DlsFlsRequestValve;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesInterceptor;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.DefaultPrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.transport.DefaultInterClusterRequestEvaluator;
import com.amazon.opendistroforelasticsearch.security.transport.InterClusterRequestEvaluator;

public class ReflectionHelper {

    protected static final Logger log = LogManager.getLogger(ReflectionHelper.class);

    private static Set<ModuleInfo> modulesLoaded = new HashSet<>();

    public static Set<ModuleInfo> getModulesLoaded() {
        return Collections.unmodifiableSet(modulesLoaded);
    }

    private static boolean enterpriseModulesDisabled() {
        return !enterpriseModulesEnabled;
    }

    public static void registerMngtRestApiHandler(final Settings settings) {

        if (enterpriseModulesDisabled()) {
            return;
        }
        
        if(!settings.getAsBoolean("http.enabled", true)) {
    
            try {
                final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.dlic.rest.api.OpenDistroSecurityRestApiActions");
                addLoadedModule(clazz);
            } catch (final Throwable e) {
                log.warn("Unable to register Rest Management Api Module due to {}", e.toString());
                if(log.isDebugEnabled()) {
                    log.debug("Stacktrace: ",e);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    public static Collection<RestHandler> instantiateMngtRestApiHandler(final Settings settings, final Path configPath, final RestController restController,
            final Client localClient, final AdminDNs adminDns, final IndexBaseConfigurationRepository cr, final ClusterService cs, final PrincipalExtractor principalExtractor,
            final PrivilegesEvaluator evaluator, final ThreadPool threadPool, final AuditLog auditlog) {

        if (enterpriseModulesDisabled()) {
            return Collections.emptyList();
        }

        try {
            final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.dlic.rest.api.OpenDistroSecurityRestApiActions");
            final Collection<RestHandler> ret = (Collection<RestHandler>) clazz
                    .getDeclaredMethod("getHandler", Settings.class, Path.class, RestController.class, Client.class, AdminDNs.class, IndexBaseConfigurationRepository.class,
                            ClusterService.class, PrincipalExtractor.class, PrivilegesEvaluator.class, ThreadPool.class, AuditLog.class)
                    .invoke(null, settings, configPath, restController, localClient, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditlog);
            addLoadedModule(clazz);
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable Rest Management Api Module due to {}", e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return Collections.emptyList();
        }
    }

    @SuppressWarnings("rawtypes")
    public static Constructor instantiateDlsFlsConstructor() {

        if (enterpriseModulesDisabled()) {
            return null;
        }

        try {
            final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.configuration.OpenDistroSecurityFlsDlsIndexSearcherWrapper");
            final Constructor<?> ret = clazz.getConstructor(IndexService.class,
                    Settings.class, AdminDNs.class, ClusterService.class, AuditLog.class,
                    ComplianceIndexingOperationListener.class, ComplianceConfig.class);
            addLoadedModule(clazz);
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable DLS/FLS Module due to {}", e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return null;
        }
    }

    public static DlsFlsRequestValve instantiateDlsFlsValve() {

        if (enterpriseModulesDisabled()) {
            return new DlsFlsRequestValve.NoopDlsFlsRequestValve();
        }

        try {
            final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.configuration.DlsFlsValveImpl");
            final DlsFlsRequestValve ret = (DlsFlsRequestValve) clazz.newInstance();
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable DLS/FLS Valve Module due to {}", e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return new DlsFlsRequestValve.NoopDlsFlsRequestValve();
        }
    }

    public static AuditLog instantiateAuditLog(final Settings settings, final Path configPath, final Client localClient, final ThreadPool threadPool,
            final IndexNameExpressionResolver resolver, final ClusterService clusterService) {

        if (enterpriseModulesDisabled()) {
            return new NullAuditLog();
        }

        try {
            final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditLogImpl");
            final AuditLog impl = (AuditLog) clazz
                    .getConstructor(Settings.class, Path.class, Client.class, ThreadPool.class, IndexNameExpressionResolver.class, ClusterService.class)
                    .newInstance(settings, configPath, localClient, threadPool, resolver, clusterService);
            addLoadedModule(clazz);
            return impl;
        } catch (final Throwable e) {
            log.warn("Unable to enable Auditlog Module due to {}", e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return new NullAuditLog();
        }
    }

    public static ComplianceIndexingOperationListener instantiateComplianceListener(ComplianceConfig complianceConfig, AuditLog auditlog) {

        if (enterpriseModulesDisabled()) {
            return new ComplianceIndexingOperationListener();
        }

        try {
            final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.compliance.ComplianceIndexingOperationListenerImpl");
            final ComplianceIndexingOperationListener impl = (ComplianceIndexingOperationListener) clazz
                    .getConstructor(ComplianceConfig.class, AuditLog.class)
                    .newInstance(complianceConfig, auditlog);
            addLoadedModule(clazz);
            return impl;
        } catch (final ClassNotFoundException e) {
            //TODO produce a single warn msg, this here is issued for every index
           log.debug("Unable to enable Compliance Module due to {}", e.toString());
           if(log.isDebugEnabled()) {
               log.debug("Stacktrace: ",e);
           }
           return new ComplianceIndexingOperationListener();
        } catch (final Throwable e) {
            log.error("Unable to enable Compliance Module due to {}", e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return new ComplianceIndexingOperationListener();
        }
    }

    public static PrivilegesInterceptor instantiatePrivilegesInterceptorImpl(final IndexNameExpressionResolver resolver, final ClusterService clusterService,
            final Client localClient, final ThreadPool threadPool) {

        final PrivilegesInterceptor noop = new PrivilegesInterceptor(resolver, clusterService, localClient, threadPool);

        if (enterpriseModulesDisabled()) {
            return noop;
        }

        try {
            final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.configuration.PrivilegesInterceptorImpl");
            final PrivilegesInterceptor ret = (PrivilegesInterceptor) clazz.getConstructor(IndexNameExpressionResolver.class, ClusterService.class, Client.class, ThreadPool.class)
                    .newInstance(resolver, clusterService, localClient, threadPool);
            addLoadedModule(clazz);
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable Kibana Module due to {}", e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return noop;
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T instantiateAAA(final String clazz, final Settings settings, final Path configPath, final boolean checkEnterprise) {

        if (checkEnterprise && enterpriseModulesDisabled()) {
            throw new ElasticsearchException("Can not load '{}' because enterprise modules are disabled", clazz);
        }

        try {
            final Class<?> clazz0 = Class.forName(clazz);
            final T ret = (T) clazz0.getConstructor(Settings.class, Path.class).newInstance(settings, configPath);

            addLoadedModule(clazz0);

            return ret;

        } catch (final Throwable e) {
            log.warn("Unable to enable '{}' due to {}", clazz, e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            throw new ElasticsearchException(e);
        }
    }

    public static InterClusterRequestEvaluator instantiateInterClusterRequestEvaluator(final String clazz, final Settings settings) {

        try {
            final Class<?> clazz0 = Class.forName(clazz);
            final InterClusterRequestEvaluator ret = (InterClusterRequestEvaluator) clazz0.getConstructor(Settings.class).newInstance(settings);
            addLoadedModule(clazz0);
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to load inter cluster request evaluator '{}' due to {}", clazz, e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return new DefaultInterClusterRequestEvaluator(settings);
        }
    }

    public static PrincipalExtractor instantiatePrincipalExtractor(final String clazz) {

        try {
            final Class<?> clazz0 = Class.forName(clazz);
            final PrincipalExtractor ret = (PrincipalExtractor) clazz0.newInstance();
            addLoadedModule(clazz0);
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to load pricipal extractor '{}' due to {}", clazz, e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            return new DefaultPrincipalExtractor();
        }
    }

    public static boolean isEnterpriseAAAModule(final String clazz) {
        boolean enterpriseModuleInstalled = false;

        if (clazz.equalsIgnoreCase("com.amazon.dlic.auth.ldap.backend.LDAPAuthorizationBackend")) {
            enterpriseModuleInstalled = true;
        }

        if (clazz.equalsIgnoreCase("com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend")) {
            enterpriseModuleInstalled = true;
        }

        if (clazz.equalsIgnoreCase("com.amazon.dlic.auth.http.jwt.HTTPJwtAuthenticator")) {
            enterpriseModuleInstalled = true;
        }
        
        if (clazz.equalsIgnoreCase("com.amazon.dlic.auth.http.jwt.keybyoidc.HTTPJwtKeyByOpenIdConnectAuthenticator")) {
            enterpriseModuleInstalled = true;
        }

        if (clazz.equalsIgnoreCase("com.amazon.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator")) {
            enterpriseModuleInstalled = true;
        }
        
        if (clazz.equalsIgnoreCase("com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator")) {
            enterpriseModuleInstalled = true;
        }

        return enterpriseModuleInstalled;
    }

    public static boolean addLoadedModule(Class<?> clazz) {
        ModuleInfo moduleInfo = getModuleInfo(clazz);
        if (log.isDebugEnabled()) {
            log.debug("Loaded module {}", moduleInfo);
        }
        return modulesLoaded.add(moduleInfo);
    }

    private static boolean enterpriseModulesEnabled;

    // TODO static hack
    public static void init(final boolean enterpriseModulesEnabled) {
        ReflectionHelper.enterpriseModulesEnabled = enterpriseModulesEnabled;
    }

    private static ModuleInfo getModuleInfo(final Class<?> impl) {

        ModuleType moduleType = ModuleType.getByDefaultImplClass(impl);
        ModuleInfo moduleInfo = new ModuleInfo(moduleType, impl.getName());

        try {

            final String classPath = impl.getResource(impl.getSimpleName() + ".class").toString();
            moduleInfo.setClasspath(classPath);

            if (!classPath.startsWith("jar")) {
                return moduleInfo;
            }

            final String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) + "/META-INF/MANIFEST.MF";

            try (InputStream stream = new URL(manifestPath).openStream()) {
                final Manifest manifest = new Manifest(stream);
                final Attributes attr = manifest.getMainAttributes();
                moduleInfo.setVersion(attr.getValue("Implementation-Version"));
                moduleInfo.setBuildTime(attr.getValue("Build-Time"));
                moduleInfo.setGitsha1(attr.getValue("git-sha1"));
            }
        } catch (final Throwable e) {
            log.error("Unable to retrieve module info for " + impl, e);
        }

        return moduleInfo;
    }
}
