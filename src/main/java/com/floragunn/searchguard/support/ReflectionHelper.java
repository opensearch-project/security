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

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.inject.util.Providers;
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
    
    private static boolean enterpriseModulesDisabled() {
        return !enterpriseModulesEnabled;
    }
    
    @SuppressWarnings("unchecked")
    public static Collection<RestHandler> instantiateMngtRestApiHandler(Settings settings
            , RestController restController, Client localClient, AdminDNs adminDns, IndexBaseConfigurationRepository cr,
            ClusterService cs, PrincipalExtractor principalExtractor) {
        
        if(enterpriseModulesDisabled()) {
           return Collections.emptyList(); 
        }
        
        try{
          return (Collection<RestHandler>) (Class
                    .forName("com.floragunn.searchguard.dlic.rest.api.SearchGuardRestApiActions")
                    .getDeclaredMethod("getHandler", Settings.class, RestController.class, Client.class, 
                                       AdminDNs.class, IndexBaseConfigurationRepository.class, ClusterService.class, PrincipalExtractor.class)
                    .invoke(null, settings, restController, localClient, adminDns, cr, cs, principalExtractor));
        } catch(Throwable e){
            log.warn("Unable to enable Rest Management Api Module due to {}", e.toString());
            return Collections.emptyList(); 
        }
    }
    
    
    public static Constructor<?> instantiateDlsFlsConstructor() {
        
        if(enterpriseModulesDisabled()) {
           return null;
        }
        
        try{
          return (Constructor<?>) (Class
                    .forName("com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper")
                    .getConstructor(IndexService.class, Settings .class));
        } catch(Throwable e){
            log.warn("Unable to enable DLS/FLS Module due to {}", e.toString());
            return null;
        }
    }
    
    public static DlsFlsRequestValve instantiateDlsFlsValve() {
        
        if(enterpriseModulesDisabled()) {
           return new DlsFlsRequestValve.NoopDlsFlsRequestValve();
        }
        
        try{
          return (DlsFlsRequestValve) (Class
                    .forName("com.floragunn.searchguard.configuration.DlsFlsValveImpl")
                    .newInstance());
        } catch(Throwable e){
            log.warn("Unable to enable DLS/FLS Valve Module due to {}", e.toString());
            return new DlsFlsRequestValve.NoopDlsFlsRequestValve();
        }
    }
    
    public static AuditLog instantiateAuditLog(Settings settings, 
            Provider<Client> localClient, ThreadPool threadPool, 
            IndexNameExpressionResolver resolver, Provider<ClusterService> clusterService) {
        
        if(enterpriseModulesDisabled()) {
           return new NullAuditLog();
        }
        
        try{
            AuditLog impl = (AuditLog) (Class
                    .forName("com.floragunn.searchguard.auditlog.impl.AuditLogImpl")
                    .getConstructor(Settings.class, Provider.class , ThreadPool.class, IndexNameExpressionResolver.class, Provider.class)
                    .newInstance(settings, Providers.of(localClient), threadPool, resolver, Providers.of(clusterService)));
            
            
            String className = impl.getClass().getSimpleName() + ".class";
            String classPath = impl.getClass().getResource(className).toString();
            if (!classPath.startsWith("jar")) {
              // Class not from JAR
              //return;
            }
            String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) + 
                "/META-INF/MANIFEST.MF";
            
            try(InputStream stream = new URL(manifestPath).openStream()) {
                Manifest manifest = new Manifest(stream);
                Attributes attr = manifest.getMainAttributes();
                String value = attr.getValue("Implementation-Version");
                log.info("Loaded auditlog "+impl.getClass()+" version "+value);
            }
            return impl;
        } catch(Throwable e){
            log.warn("Unable to enable Auditlog Module due to {}", e.toString());
            return new NullAuditLog();
        }
    }
    
    public static PrivilegesInterceptor instantiatePrivilegesInterceptorImpl(IndexNameExpressionResolver resolver, 
            ClusterService clusterService, Client localClient, ThreadPool threadPool) {
        
        PrivilegesInterceptor noop = new PrivilegesInterceptor(resolver, clusterService, localClient, threadPool);
        
        if(enterpriseModulesDisabled()) {
           return noop;
        }
        
        try{
          return (PrivilegesInterceptor) (Class
                    .forName("com.floragunn.searchguard.configuration.PrivilegesInterceptorImpl")
                    .getConstructor(IndexNameExpressionResolver.class, ClusterService.class, Client.class, ThreadPool.class)
                    .newInstance(resolver, clusterService, localClient, threadPool));
        } catch(Throwable e){
            log.warn("Unable to enable Kibana Module due to {}", e.toString());
            return noop;
        }
    }
    
    @SuppressWarnings("unchecked")
    public static <T> T instantiateAAA(String clazz, Settings settings, boolean checkEnterprise) {
        
        if(checkEnterprise && enterpriseModulesDisabled()) {
           throw new ElasticsearchException("Can not load '{}' because enterprise modules are disabled");
        }
        
        try{
          return (T) (Class
                    .forName(clazz)
                    .getConstructor(Settings.class)
                    .newInstance(settings));
        } catch(Throwable e){
            log.warn("Unable to enable '{}' due to {}", clazz, e.toString());
            throw new ElasticsearchException(e);
        }
    }
    

    public static InterClusterRequestEvaluator instantiateInterClusterRequestEvaluator(String clazz, Settings settings) {
        
        try{
          return (InterClusterRequestEvaluator) (Class
                    .forName(clazz)
                    .getConstructor(Settings.class)
                    .newInstance(settings));
        } catch(Throwable e){
            log.warn("Unable to load inter cluster request evaluator '{}' due to {}", clazz, e.toString());
            return new DefaultInterClusterRequestEvaluator(settings);
        }
    }
    
    public static PrincipalExtractor instantiatePrincipalExtractor(String clazz) {
        
        try{
          return (PrincipalExtractor) (Class
                    .forName(clazz)
                    .newInstance());
        } catch(Throwable e){
            log.warn("Unable to load pricipal extractor '{}' due to {}", clazz, e.toString());
            return new DefaultPrincipalExtractor();
        }
    }
    
    public static boolean isEnterpriseAAAModule(String clazz) {
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

    //TODO static hack
    public static void init(boolean enterpriseModulesEnabled) {
        ReflectionHelper.enterpriseModulesEnabled = enterpriseModulesEnabled;
    }
    
}
