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

import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.Lifecycle.State;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsFilter;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.http.HttpServerTransport.Dispatcher;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.index.shard.SearchOperationListener;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.search.internal.ScrollContext;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.RemoteClusterService;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.Transport.Connection;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportInterceptor;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.watcher.ResourceWatcherService;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.action.licenseinfo.LicenseInfoAction;
import com.floragunn.searchguard.action.licenseinfo.TransportLicenseInfoAction;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;
import com.floragunn.searchguard.configuration.ActionGroupHolder;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ClusterInfoHolder;
import com.floragunn.searchguard.configuration.DlsFlsRequestValve;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.configuration.PrivilegesInterceptor;
import com.floragunn.searchguard.configuration.SearchGuardIndexSearcherWrapper;
import com.floragunn.searchguard.filter.SearchGuardFilter;
import com.floragunn.searchguard.filter.SearchGuardRestFilter;
import com.floragunn.searchguard.http.SearchGuardHttpServerTransport;
import com.floragunn.searchguard.http.SearchGuardNonSslHttpServerTransport;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.rest.KibanaInfoAction;
import com.floragunn.searchguard.rest.SearchGuardInfoAction;
import com.floragunn.searchguard.rest.SearchGuardLicenseAction;
import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin;
import com.floragunn.searchguard.ssl.http.netty.ValidatingDispatcher;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.ModuleInfo;
import com.floragunn.searchguard.support.ReflectionHelper;
import com.floragunn.searchguard.transport.DefaultInterClusterRequestEvaluator;
import com.floragunn.searchguard.transport.InterClusterRequestEvaluator;
import com.floragunn.searchguard.transport.SearchGuardInterceptor;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.Lists;

public final class SearchGuardPlugin extends SearchGuardSSLPlugin {
    
    private final boolean tribeNodeClient;
    private final boolean dlsFlsAvailable;
    private final Constructor<?> dlsFlsConstructor;
    private SearchGuardRestFilter sgRestHandler;
    private SearchGuardInterceptor sgi;
    private PrivilegesEvaluator evaluator;
    private ThreadPool threadPool;
    private IndexBaseConfigurationRepository cr;
    private AdminDNs adminDns;
    private ClusterService cs;
    private AuditLog auditLog;
    private Client localClient;
    private final boolean disabled;
    private final boolean enterpriseModulesEnabled;
    private static final String LB = System.lineSeparator();
    private final List<String> demoCertHashes = new ArrayList<String>(3); 

    public SearchGuardPlugin(final Settings settings, final Path configPath) {
        super(settings, configPath, settings.getAsBoolean(ConfigConstants.SEARCHGUARD_DISABLED, false));
        
        disabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_DISABLED, false);
        
        if(disabled) {
            this.tribeNodeClient = false;
            this.dlsFlsAvailable = false;
            this.dlsFlsConstructor = null;
            enterpriseModulesEnabled = false;
            log.warn("Search Guard plugin installed but disabled. This can expose your configuration (including passwords) to the public.");
            return;
        }
        
        demoCertHashes.add("54a92508de7a39d06242a0ffbf59414d7eb478633c719e6af03938daf6de8a1a");
        demoCertHashes.add("742e4659c79d7cad89ea86aab70aea490f23bbfc7e72abd5f0a5d3fb4c84d212");
        demoCertHashes.add("db1264612891406639ecd25c894f256b7c5a6b7e1d9054cbe37b77acd2ddd913");
        demoCertHashes.add("2a5398e20fcb851ec30aa141f37233ee91a802683415be2945c3c312c65c97cf");
        demoCertHashes.add("33129547ce617f784c04e965104b2c671cce9e794d1c64c7efe58c77026246ae");
        demoCertHashes.add("c4af0297cc75546e1905bdfe3934a950161eee11173d979ce929f086fdf9794d");
        demoCertHashes.add("7a355f42c90e7543a267fbe3976c02f619036f5a34ce712995a22b342d83c3ce");
        demoCertHashes.add("a9b5eca1399ec8518081c0d4a21a34eec4589087ce64c04fb01a488f9ad8edc9");
        
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                if(Security.getProvider("BC") == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }
                return null;
            }
        });
        
        enterpriseModulesEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_ENTERPRISE_MODULES_ENABLED, true);
        ReflectionHelper.init(enterpriseModulesEnabled);

        log.info("Clustername: {}", settings.get("cluster.name","elasticsearch"));

        final String licenseText =
        
        LB+"### LICENSE NOTICE Search Guard ###"+LB+LB+

        "If you use one or more of the following features in production"+LB+
        "make sure you have a valid Search Guard license"+LB+
        "(See https://floragunn.com/searchguard-validate-license)"+LB+LB+

        "* Kibana Multitenancy"+LB+
        "* LDAP authentication/authorization"+LB+
        "* Active Directory authentication/authorization"+LB+
        "* REST Management API"+LB+
        "* JSON Web Token (JWT) authentication/authorization"+LB+
        "* Kerberos authentication/authorization"+LB+
        "* Document- and Fieldlevel Security (DLS/FLS)"+LB+
        "* Auditlogging"+LB+LB+

        "In case of any doubt mail to <sales@floragunn.com>"+LB+
        "###################################";
        
        if(!Boolean.getBoolean("sg.display_lic_none")) {
            
            if(!Boolean.getBoolean("sg.display_lic_only_stdout")) {
                log.warn(licenseText);
                System.err.println(licenseText);
            }
    
            System.out.println(licenseText);

        }

        if(!transportSSLEnabled) {
            throw new IllegalStateException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }
        
        if(log.isDebugEnabled() && this.settings.getByPrefix("tribe").getAsMap().size() > 0) {
            log.debug("Tribe configuration detected: {}", this.settings.getAsMap());
        }
        
        boolean tribeNode = this.settings.get("tribe.name", null) == null && this.settings.getByPrefix("tribe").getAsMap().size() > 0;
        tribeNodeClient = this.settings.get("tribe.name", null) != null;

        log.debug("This node [{}] is a transportClient: {}/tribeNode: {}/tribeNodeClient: {}", settings.get("node.name"), client, tribeNode, tribeNodeClient);

        if(!client) {
            dlsFlsConstructor = ReflectionHelper.instantiateDlsFlsConstructor();
            dlsFlsAvailable = dlsFlsConstructor != null;
        } else {
            dlsFlsAvailable = false;
            dlsFlsConstructor = null;
        }

        if(!client && !tribeNodeClient && !settings.getAsBoolean(ConfigConstants.SEARCHGUARD_ALLOW_UNSAFE_DEMOCERTIFICATES, false)) {
            //check for demo certificates
            final List<String> files = AccessController.doPrivileged(new PrivilegedAction<List<String>>() {
                @Override
                public List<String> run() {
                  final Path confPath = new Environment(settings, configPath).configFile().toAbsolutePath();
                    if(Files.isDirectory(confPath, LinkOption.NOFOLLOW_LINKS)) {
                        try {
                            return Files.walk(confPath)
                            .distinct()
                            .map(p->sha256(p))
                            .collect(Collectors.toList());
                        } catch (Exception e) {
                            log.error(e);
                            return null;
                        }
                    }
                    
                    return Collections.emptyList();
                }
            });
            
            if(files != null) {
                demoCertHashes.retainAll(files);
                if(!demoCertHashes.isEmpty()) {
                    throw new RuntimeException("Demo certificates found "+demoCertHashes);
                }
            } else {
                throw new RuntimeException("Unable to look for demo certificates");
            }
            
        }
    }
    
    private String sha256(Path p) {
        
        if(!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
            return "";
        }

        try {
            MessageDigest digester = MessageDigest.getInstance("SHA256");
            final String hash = org.bouncycastle.util.encoders.Hex.toHexString(digester.digest(Files.readAllBytes(p)));
            log.debug(hash +" :: "+p);
            return hash;
        } catch (Exception e) {
            throw new ElasticsearchSecurityException("Unable to digest file", e);
        }
    }
    
    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {
        
        final List<RestHandler> handlers = new ArrayList<RestHandler>(1);
        
        if (!client && !tribeNodeClient && !disabled) {
            
            handlers.addAll(super.getRestHandlers(settings, restController, clusterSettings, indexScopedSettings, settingsFilter, indexNameExpressionResolver, nodesInCluster));

            handlers.add(new SearchGuardInfoAction(settings, restController, Objects.requireNonNull(evaluator), Objects.requireNonNull(threadPool)));
            handlers.add(new KibanaInfoAction(settings, restController, Objects.requireNonNull(evaluator), Objects.requireNonNull(threadPool)));
            handlers.add(new SearchGuardLicenseAction(settings, restController));

            Collection<RestHandler> apiHandler = ReflectionHelper
                    .instantiateMngtRestApiHandler(settings, configPath, restController, localClient, adminDns, cr, cs, Objects.requireNonNull(principalExtractor),  evaluator, threadPool);
            handlers.addAll(apiHandler);
            log.debug("Added {} management rest handler(s)", apiHandler.size());
        }
        
        
        final Set<ModuleInfo> sgModules = ReflectionHelper.getModulesLoaded();
        
        log.info("{} Search Guard modules loaded so far: {}", sgModules.size(), sgModules);
        
        return handlers;
    }
    
    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(final ThreadContext threadContext) {
        
        if(client || disabled) {
            return (rh) -> rh;
        }
        
        return (rh) -> sgRestHandler.wrap(rh);
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> actions = new ArrayList<>(1);
        if(!tribeNodeClient && !disabled) {
            actions.add(new ActionHandler<>(ConfigUpdateAction.INSTANCE, TransportConfigUpdateAction.class));
            actions.add(new ActionHandler<>(LicenseInfoAction.INSTANCE, TransportLicenseInfoAction.class));
        }
        return actions;
    }

    private IndexSearcherWrapper loadFlsDlsIndexSearcherWrapper(final IndexService indexService) {
        try {
            IndexSearcherWrapper flsdlsWrapper = (IndexSearcherWrapper) dlsFlsConstructor.newInstance(indexService, settings, Objects.requireNonNull(adminDns));
            if(log.isDebugEnabled()) {
                log.debug("FLS/DLS enabled for index {}", indexService.index().getName());
            }
            return flsdlsWrapper;
        } catch(Exception ex) {
            throw new RuntimeException("Failed to enable FLS/DLS", ex);
        }
    }
    
    @Override
    public void onIndexModule(IndexModule indexModule) {
        //called for every index!
        
        if (!disabled && !client) {
            if (dlsFlsAvailable) {
                indexModule.setSearcherWrapper(indexService -> loadFlsDlsIndexSearcherWrapper(indexService));
            } else {
                indexModule.setSearcherWrapper(indexService -> new SearchGuardIndexSearcherWrapper(indexService, settings, Objects
                        .requireNonNull(adminDns)));
            }
        
            //TODO SG6 check SearchOperationListener for read/scroll 
            indexModule.addSearchOperationListener(new SearchOperationListener() {

                @Override
                public void onNewScrollContext(SearchContext context) {
                    
                    final ScrollContext scrollContext = context.scrollContext();
                    
                    if(scrollContext != null) {
                        scrollContext.putInContext("_sg_scroll_auth", threadPool.getThreadContext()
                                .getTransient(ConfigConstants.SG_USER));
                    }
                }

                @Override
                public void validateSearchContext(SearchContext context, TransportRequest transportRequest) {
                    
                    final ScrollContext scrollContext = context.scrollContext();
                    if(scrollContext != null) {
                        final Object _user = scrollContext.getFromContext("_sg_scroll_auth");
                        if(_user != null && (_user instanceof User)) {
                            final User scrollUser = (User) _user;
                            final User currentUser = threadPool.getThreadContext()
                                    .getTransient(ConfigConstants.SG_USER);
                            if(!scrollUser.equals(currentUser)) {
                                log.error("Wrong user {} in scroll context, expected {}", scrollUser, currentUser);
                                throw new ElasticsearchException("Wrong user in scroll context");
                            }
                        } else {
                            throw new ElasticsearchException("No user in scroll context");
                        }
                    }
                }
            });
        }
    }
    
    @Override
    public List<Class<? extends ActionFilter>> getActionFilters() {
        List<Class<? extends ActionFilter>> filters = new ArrayList<>(1);
        if (!tribeNodeClient && !client && !disabled) {
            filters.add(SearchGuardFilter.class);
        }
        return filters;
    }

    @Override
    public List<TransportInterceptor> getTransportInterceptors(NamedWriteableRegistry namedWriteableRegistry, ThreadContext threadContext) {
        List<TransportInterceptor> interceptors = new ArrayList<TransportInterceptor>(1);
        
        if (!client && !tribeNodeClient && !disabled) {            
            interceptors.add(new TransportInterceptor() {

                @Override
                public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(String action, String executor,
                        boolean forceExecution, TransportRequestHandler<T> actualHandler) {
                    
                    return new TransportRequestHandler<T>() {

                        @Override
                        public void messageReceived(T request, TransportChannel channel, Task task) throws Exception {
                            sgi.getHandler(action, actualHandler).messageReceived(request, channel, task);
                        }

                        @Override
                        public void messageReceived(T request, TransportChannel channel) throws Exception {
                            sgi.getHandler(action, actualHandler).messageReceived(request, channel);
                        }
                    };
                    
                }

                @Override
                public AsyncSender interceptSender(AsyncSender sender) {
                    
                    return new AsyncSender() {

                        @Override
                        public <T extends TransportResponse> void sendRequest(Connection connection, String action,
                                TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {
                            sgi.sendRequestDecorate(sender, connection, action, request, options, handler);
                        }
                    };
                }
            });
        }
        
        return interceptors;
    }
    
    @Override
    public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {        
        return super.getTransports(settings, threadPool, bigArrays, circuitBreakerService, namedWriteableRegistry, networkService);
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry,
            NamedXContentRegistry xContentRegistry, NetworkService networkService, Dispatcher dispatcher) {
        
        Map<String, Supplier<HttpServerTransport>> httpTransports = new HashMap<String, Supplier<HttpServerTransport>>(1);

        if(!disabled) {
            if (!client && httpSSLEnabled && !tribeNodeClient) {
                
                final ValidatingDispatcher validatingDispatcher = new ValidatingDispatcher(threadPool.getThreadContext(), dispatcher, settings, configPath);
                final SearchGuardHttpServerTransport sghst = new SearchGuardHttpServerTransport(settings, networkService, bigArrays, threadPool, sgks, auditLog, xContentRegistry, validatingDispatcher);
                validatingDispatcher.setAuditErrorHandler(sghst);
                
                httpTransports.put("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", 
                        () -> sghst);
            } else if (!client && !tribeNodeClient) {
                httpTransports.put("com.floragunn.searchguard.http.SearchGuardHttpServerTransport", 
                        () -> new SearchGuardNonSslHttpServerTransport(settings, networkService, bigArrays, threadPool, xContentRegistry, dispatcher));
            }
        }
        return httpTransports;
    }
    
    
        
    @Override
    public Collection<Object> createComponents(Client localClient, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry,
            Environment environment, NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry) {
        
        this.threadPool = threadPool;
        this.cs = clusterService;
        this.localClient = localClient;
        
        final List<Object> components = new ArrayList<Object>();
        
        if (client || tribeNodeClient || disabled) {
            return components;
        }
        
        final ClusterInfoHolder cih = new ClusterInfoHolder();
        this.cs.addListener(cih);
        
        DlsFlsRequestValve dlsFlsValve = ReflectionHelper.instantiateDlsFlsValve();
        
        final IndexNameExpressionResolver resolver = new IndexNameExpressionResolver(settings);
        auditLog = ReflectionHelper.instantiateAuditLog(settings, configPath, localClient, threadPool, resolver, clusterService);
        
        final String DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = DefaultInterClusterRequestEvaluator.class.getName();
        InterClusterRequestEvaluator interClusterRequestEvaluator = new DefaultInterClusterRequestEvaluator(settings);

     
        final String className = settings.get(ConfigConstants.SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS);
        log.debug("Using {} as intercluster request evaluator class", className);
        if (!DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS.equals(className)) {
            interClusterRequestEvaluator = ReflectionHelper.instantiateInterClusterRequestEvaluator(className, settings);
        }
        
        final PrivilegesInterceptor privilegesInterceptor = ReflectionHelper.instantiatePrivilegesInterceptorImpl(resolver, clusterService, localClient, threadPool);

        adminDns = new AdminDNs(settings);      
        //final PrincipalExtractor pe = new DefaultPrincipalExtractor();        
        cr = (IndexBaseConfigurationRepository) IndexBaseConfigurationRepository.create(settings, this.configPath, threadPool, localClient, clusterService);        
        final InternalAuthenticationBackend iab = new InternalAuthenticationBackend(cr);     
        final XFFResolver xffResolver = new XFFResolver(threadPool);
        cr.subscribeOnChange(ConfigConstants.CONFIGNAME_CONFIG, xffResolver);   
        final BackendRegistry backendRegistry = new BackendRegistry(settings, configPath, adminDns, xffResolver, iab, auditLog, threadPool);
        cr.subscribeOnChange(ConfigConstants.CONFIGNAME_CONFIG, backendRegistry);
        final ActionGroupHolder ah = new ActionGroupHolder(cr);      
        evaluator = new PrivilegesEvaluator(clusterService, threadPool, cr, ah, resolver, auditLog, settings, privilegesInterceptor, cih);    
        final SearchGuardFilter sgf = new SearchGuardFilter(settings, evaluator, adminDns, dlsFlsValve, auditLog, threadPool, cs);     
        
        
        final String principalExtractorClass = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, null);

        if(principalExtractorClass == null) {
            principalExtractor = new com.floragunn.searchguard.ssl.transport.DefaultPrincipalExtractor();
        } else {
            principalExtractor = ReflectionHelper.instantiatePrincipalExtractor(principalExtractorClass);
        }
        
        sgi = new SearchGuardInterceptor(settings, threadPool, backendRegistry, auditLog, principalExtractor, interClusterRequestEvaluator, cs);
        components.add(principalExtractor);
        
        
        components.add(adminDns);
        //components.add(auditLog);
        components.add(cr);
        components.add(iab);
        components.add(xffResolver);
        components.add(backendRegistry);
        components.add(ah);
        components.add(evaluator);
        components.add(sgf);
        components.add(sgi);

        sgRestHandler = new SearchGuardRestFilter(backendRegistry, auditLog, threadPool, principalExtractor, settings, configPath);
        
        return components;
        
    }

    @Override
    public Settings additionalSettings() {
        
        if(disabled) {
            return Settings.EMPTY;
        }
        
        final Settings.Builder builder = Settings.builder();
        builder.put(NetworkModule.TRANSPORT_TYPE_KEY, "com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyTransport");
        builder.put(NetworkModule.HTTP_TYPE_KEY, "com.floragunn.searchguard.http.SearchGuardHttpServerTransport");
        return builder.build();
    }
    
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        
        settings.addAll(super.getSettings());
        
        settings.add(Setting.listSetting(ConfigConstants.SEARCHGUARD_AUTHCZ_ADMIN_DN, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here

        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, Property.NodeScope, Property.Filtered));
        settings.add(Setting.groupSetting(ConfigConstants.SEARCHGUARD_AUTHCZ_IMPERSONATION_DN+".", Property.NodeScope)); //not filtered here

        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_INDEX, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_USERNAME, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_DISABLED_CATEGORIES, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
        settings.add(Setting.intSetting(ConfigConstants.SEARCHGUARD_AUDIT_THREADPOOL_MAX_QUEUE_LEN, 100*1000, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_ENABLE_REST, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_ENABLE_TRANSPORT, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.SEARCHGUARD_AUDIT_THREADPOOL_SIZE, 10, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_ENABLE_REQUEST_DETAILS, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_WEBHOOK_SSL_VERIFY, true, Property.NodeScope, Property.Filtered));
        //settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_WEBHOOK_URL2, Property.NodeScope, Property.Filtered));
        //settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_WEBHOOK_FORMAT2, Property.NodeScope, Property.Filtered));
        
        
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_KERBEROS_KRB5_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_KERBEROS_ACCEPTOR_PRINCIPAL, Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.listSetting(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_HTTP_ENDPOINTS, Lists.newArrayList("localhost:9200"), Function.identity(), Property.NodeScope)); //not filtered here
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_ENABLE_SSL, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_VERIFY_HOSTNAMES, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_ENABLE_SSL_CLIENT_AUTH, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_WEBHOOK_URL, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_WEBHOOK_FORMAT, Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_CERT_OID, Property.NodeScope, Property.Filtered));

        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.SEARCHGUARD_NODES_DN, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here

        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, ConfigConstants.SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, ConfigConstants.SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                Property.NodeScope, Property.Filtered));

        settings.add(Setting.listSetting(ConfigConstants.SEARCHGUARD_AUDIT_IGNORE_USERS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
        
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_DISABLED, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.SEARCHGUARD_CACHE_TTL_MINUTES, 60, 0, Property.NodeScope, Property.Filtered));

        //SG6
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_ENTERPRISE_MODULES_ENABLED, true, Property.NodeScope, Property.Filtered));    
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_ALLOW_UNSAFE_DEMOCERTIFICATES, false, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_ALLOW_DEFAULT_INIT_SGINDEX, false, Property.NodeScope, Property.Filtered));
        
        settings.add(Setting.groupSetting(ConfigConstants.SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS+".", Property.NodeScope)); //not filtered here

        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_DISABLE_TYPE_SECURITY, false, Property.NodeScope, Property.Filtered));

        //TODO remove searchguard.tribe.clustername?
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_TRIBE_CLUSTERNAME, Property.NodeScope, Property.Filtered));
        
        // SG6 - Audit
        settings.add(Setting.boolSetting(ConfigConstants.SEARCHGUARD_AUDIT_RESOLVE_BULK_REQUESTS, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_LOG4J_LOGGER_NAME, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_LOG4J_LEVEL, Property.NodeScope, Property.Filtered));
        
        // SG6 - REST API
        settings.add(Setting.listSetting(ConfigConstants.SEARCHGUARD_RESTAPI_ROLES_ENABLED, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
        settings.add(Setting.groupSetting(ConfigConstants.SEARCHGUARD_RESTAPI_ENDPOINTS_DISABLED + ".", Property.NodeScope));

        return settings;
    }
    
    @Override
    public List<String> getSettingsFilter() {
        List<String> settingsFilter = new ArrayList<>();
        
        if(disabled) {
            return settingsFilter;
        }
        
        settingsFilter.add("searchguard.*");
        return settingsFilter;
    }

    //below is a hack because it seems not possible to access RepositoriesService from a non guice class
    //the way of how deguice is organized is really a mess - hope this can be fixed in later versions
    //TODO check if this could be removed
    
    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {

        if (client || tribeNodeClient || disabled) {
            return Collections.emptyList();
        }
        
        final List<Class<? extends LifecycleComponent>> services = new ArrayList<>(1);
        services.add(GuiceHolder.class);
        return services;
    }
    
    public static class GuiceHolder implements LifecycleComponent {

        private static RepositoriesService repositoriesService;
        private static RemoteClusterService remoteClusterService;
        
        @Inject
        public GuiceHolder(final RepositoriesService repositoriesService, 
                final TransportService remoteClusterService) {
            GuiceHolder.repositoriesService = repositoriesService;
            GuiceHolder.remoteClusterService = remoteClusterService.getRemoteClusterService();
        }

        public static RepositoriesService getRepositoriesService() {
            return repositoriesService;
        }
        
        public static RemoteClusterService getRemoteClusterService() {
            return remoteClusterService;
        }

        @Override
        public void close() {            
        }

        @Override
        public State lifecycleState() {
            return null;
        }

        @Override
        public void addLifecycleListener(LifecycleListener listener) {            
        }

        @Override
        public void removeLifecycleListener(LifecycleListener listener) {            
        }

        @Override
        public void start() {            
        }

        @Override
        public void stop() {            
        }
        
    }
}
