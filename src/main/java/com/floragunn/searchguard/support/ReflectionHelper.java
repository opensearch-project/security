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

package com.floragunn.searchguard.support;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
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

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.NullAuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.DlsFlsRequestValve;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.configuration.PrivilegesInterceptor;
import com.floragunn.searchguard.ssl.transport.DefaultPrincipalExtractor;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.transport.DefaultInterClusterRequestEvaluator;
import com.floragunn.searchguard.transport.InterClusterRequestEvaluator;

public class ReflectionHelper {

    protected static final Logger log = LogManager.getLogger(ReflectionHelper.class);

    /*public static boolean canLoad0(String clazz) {
        try {
            return Class.forName--(clazz) != null;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }


    public static Class load0(String clazz) {
        try {
            return Class.forName--(clazz);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }*/

    private static Map<String, Object> modulesLoaded = new HashMap<>();
    
    public static Map<String, Object> getModulesLoaded() {
        return Collections.unmodifiableMap(modulesLoaded);
    }

    private static boolean enterpriseModulesDisabled() {
        return !enterpriseModulesEnabled;
    }

    @SuppressWarnings("unchecked")
    public static Collection<RestHandler> instantiateMngtRestApiHandler(final Settings settings, final Path configPath, final RestController restController,
            final Client localClient, final AdminDNs adminDns, final IndexBaseConfigurationRepository cr, final ClusterService cs,
            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool) {

        if (enterpriseModulesDisabled()) {
            return Collections.emptyList();
        }

        try {
            final Class<?> clazz = Class.forName("com.floragunn.searchguard.dlic.rest.api.SearchGuardRestApiActions");
            final Collection<RestHandler> ret = (Collection<RestHandler>) clazz.getDeclaredMethod("getHandler", Settings.class,
                    Path.class, RestController.class, Client.class, AdminDNs.class, IndexBaseConfigurationRepository.class, ClusterService.class,
                    PrincipalExtractor.class, PrivilegesEvaluator.class, ThreadPool.class)
            		.invoke(null, settings, configPath, restController, localClient, adminDns, cr, cs, principalExtractor, evaluator,  threadPool);
            modulesLoaded.put("rest-mngt-api", getModuleInfo(clazz));
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable Rest Management Api Module due to {}", e.toString());
            return Collections.emptyList();
        }
    }

    public static Constructor<?> instantiateDlsFlsConstructor() {

        if (enterpriseModulesDisabled()) {
            return null;
        }

        try {
            final Class<?> clazz = Class.forName("com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper");
            final Constructor<?> ret = clazz.getConstructor(IndexService.class, Settings.class, AdminDNs.class);
            modulesLoaded.put("dls-fls", getModuleInfo(clazz));
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable DLS/FLS Module due to {}", e.toString());
            return null;
        }
    }

    public static DlsFlsRequestValve instantiateDlsFlsValve() {

        if (enterpriseModulesDisabled()) {
            return new DlsFlsRequestValve.NoopDlsFlsRequestValve();
        }

        try {
            final Class<?> clazz = Class.forName("com.floragunn.searchguard.configuration.DlsFlsValveImpl");
            final DlsFlsRequestValve ret = (DlsFlsRequestValve) clazz.newInstance();
            //modulesLoaded.put("dls-fls-valve", getModuleInfo(clazz));
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable DLS/FLS Valve Module due to {}", e.toString());
            return new DlsFlsRequestValve.NoopDlsFlsRequestValve();
        }
    }

    public static AuditLog instantiateAuditLog(final Settings settings, final Path configPath, final Client localClient, final ThreadPool threadPool,
            final IndexNameExpressionResolver resolver, final ClusterService clusterService) {

        if (enterpriseModulesDisabled()) {
            return new NullAuditLog();
        }

        try {
            final Class<?> clazz = Class.forName("com.floragunn.searchguard.auditlog.impl.AuditLogImpl");
            final AuditLog impl = (AuditLog) clazz.getConstructor(Settings.class, Path.class, Client.class, ThreadPool.class,
                    IndexNameExpressionResolver.class, ClusterService.class).newInstance(settings, configPath, localClient, threadPool,
                            resolver, clusterService);

            modulesLoaded.put("auditlog", getModuleInfo(clazz));
            return impl;
        } catch (final Throwable e) {
            log.warn("Unable to enable Auditlog Module due to {}", e.toString());
            return new NullAuditLog();
        }
    }

    public static PrivilegesInterceptor instantiatePrivilegesInterceptorImpl(final IndexNameExpressionResolver resolver,
            final ClusterService clusterService, final Client localClient, final ThreadPool threadPool) {

        final PrivilegesInterceptor noop = new PrivilegesInterceptor(resolver, clusterService, localClient, threadPool);

        if (enterpriseModulesDisabled()) {
            return noop;
        }

        try {
            final Class<?> clazz = Class.forName("com.floragunn.searchguard.configuration.PrivilegesInterceptorImpl");
            final PrivilegesInterceptor ret = (PrivilegesInterceptor) clazz.getConstructor(IndexNameExpressionResolver.class,
                    ClusterService.class, Client.class, ThreadPool.class).newInstance(resolver, clusterService, localClient, threadPool);
            modulesLoaded.put("multitenancy", getModuleInfo(clazz));
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to enable Kibana Module due to {}", e.toString());
            return noop;
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T instantiateAAA(final String clazz, final Settings settings, final Path configPath, final boolean checkEnterprise) {

        if (checkEnterprise && enterpriseModulesDisabled()) {
            throw new ElasticsearchException("Can not load '{}' because enterprise modules are disabled");
        }

        try {
            final Class<?> clazz0 = Class.forName(clazz);
            final T ret = (T) clazz0.getConstructor(Settings.class, Path.class).newInstance(settings, configPath);

            if (checkEnterprise) {
                modulesLoaded.put(clazz, getModuleInfo(clazz0));
            }

            return ret;

        } catch (final Throwable e) {
            log.warn("Unable to enable '{}' due to {}", clazz, e.toString());
            throw new ElasticsearchException(e);
        }
    }

    public static InterClusterRequestEvaluator instantiateInterClusterRequestEvaluator(final String clazz, final Settings settings) {

        try {
            final Class<?> clazz0 = Class.forName(clazz);
            final InterClusterRequestEvaluator ret = (InterClusterRequestEvaluator) clazz0.getConstructor(Settings.class).newInstance(
                    settings);
            modulesLoaded.put("cluster-request-evaluator", getModuleInfo(clazz0));
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to load inter cluster request evaluator '{}' due to {}", clazz, e.toString());
            return new DefaultInterClusterRequestEvaluator(settings);
        }
    }

    public static PrincipalExtractor instantiatePrincipalExtractor(final String clazz) {

        try {
            final Class<?> clazz0 = Class.forName(clazz);
            final PrincipalExtractor ret = (PrincipalExtractor) clazz0.newInstance();
            modulesLoaded.put("principal-extractor", getModuleInfo(clazz0));
            return ret;
        } catch (final Throwable e) {
            log.warn("Unable to load pricipal extractor '{}' due to {}", clazz, e.toString());
            return new DefaultPrincipalExtractor();
        }
    }

    public static boolean isEnterpriseAAAModule(final String clazz) {
        boolean enterpriseModuleInstalled = false;

        if (clazz.equalsIgnoreCase("com.floragunn.dlic.auth.ldap.backend.LDAPAuthorizationBackend")) {
            enterpriseModuleInstalled = true;
        }

        if (clazz.equalsIgnoreCase("com.floragunn.dlic.auth.ldap.backend.LDAPAuthenticationBackend")) {
            enterpriseModuleInstalled = true;
        }

        if (clazz.equalsIgnoreCase("com.floragunn.dlic.auth.http.jwt.HTTPJwtAuthenticator")) {
            enterpriseModuleInstalled = true;
        }

        if (clazz.equalsIgnoreCase("com.floragunn.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator")) {
            enterpriseModuleInstalled = true;
        }

        return enterpriseModuleInstalled;
    }

    private static boolean enterpriseModulesEnabled;

    // TODO static hack
    public static void init(final boolean enterpriseModulesEnabled) {
        ReflectionHelper.enterpriseModulesEnabled = enterpriseModulesEnabled;
    }

    private static Map<String, String> getModuleInfo(final Class<?> impl) {
        final Map<String, String> ret = new HashMap<String, String>();

        try {
            //final String jarPath = new File(impl.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()).getParentFile().getAbsolutePath();

            final String className = impl.getSimpleName() + ".class";
            final String classPath = impl.getResource(className).toString();
            //ret.put("class", className);
            //ret.put("classpath", classPath);
            //ret.put("jarPath", jarPath);
            if (!classPath.startsWith("jar")) {
                return ret;
            }

            final String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) + "/META-INF/MANIFEST.MF";

            try (InputStream stream = new URL(manifestPath).openStream()) {
                final Manifest manifest = new Manifest(stream);
                final Attributes attr = manifest.getMainAttributes();
                ret.put("version", attr.getValue("Implementation-Version"));
                ret.put("Build-Time", attr.getValue("Build-Time"));                
            }
        } catch (final Throwable e) {
            log.error("Unable to retrieve module info for " + impl, e);
            ret.put("error", e.toString());
        }

        return ret;
    }
}
