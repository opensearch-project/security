package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.net.InetAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;

import com.amazon.opendistroforelasticsearch.security.auth.AuthDomain;
import com.amazon.opendistroforelasticsearch.security.auth.AuthFailureListener;
import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.AuthorizationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.Destroyable;
import com.amazon.opendistroforelasticsearch.security.auth.HTTPAuthenticator;
import com.amazon.opendistroforelasticsearch.security.auth.blocking.ClientBlockRegistry;
import com.amazon.opendistroforelasticsearch.security.auth.internal.InternalAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7.Authc;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7.AuthcDomain;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7.Authz;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7.AuthzDomain;
import com.amazon.opendistroforelasticsearch.security.support.ReflectionHelper;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;

public class DynamicConfigModelV7 extends DynamicConfigModel {
    
    private final ConfigV7 config;
    private final Settings esSettings;
    private final Path configPath;
    private SortedSet<AuthDomain> restAuthDomains;
    private Set<AuthorizationBackend> restAuthorizers;
    private SortedSet<AuthDomain> transportAuthDomains;
    private Set<AuthorizationBackend> transportAuthorizers;
    private List<Destroyable> destroyableComponents;
    private final InternalAuthenticationBackend iab;

    private List<AuthFailureListener> ipAuthFailureListeners;
    private Multimap<String, AuthFailureListener> authBackendFailureListeners;
    private List<ClientBlockRegistry<InetAddress>> ipClientBlockRegistries;
    private Multimap<String, ClientBlockRegistry<String>> authBackendClientBlockRegistries;
    
    public DynamicConfigModelV7(ConfigV7 config, Settings esSettings, Path configPath, InternalAuthenticationBackend iab) {
        super();
        this.config = config;
        this.esSettings =  esSettings;
        this.configPath = configPath;
        this.iab = iab;
        buildAAA();
    }
    @Override
    public SortedSet<AuthDomain> getRestAuthDomains() {
        return Collections.unmodifiableSortedSet(restAuthDomains);
    }
    @Override
    public Set<AuthorizationBackend> getRestAuthorizers() {
        return Collections.unmodifiableSet(restAuthorizers);
    }
    @Override
    public SortedSet<AuthDomain> getTransportAuthDomains() {
        return Collections.unmodifiableSortedSet(transportAuthDomains);
    }
    @Override
    public Set<AuthorizationBackend> getTransportAuthorizers() {
        return Collections.unmodifiableSet(transportAuthorizers);
    }
    @Override
    public String getTransportUsernameAttribute() {
        return config.dynamic.transport_userrname_attribute;
    }
    @Override
    public boolean isAnonymousAuthenticationEnabled() {
        return config.dynamic.http.anonymous_auth_enabled;
    }
    @Override
    public boolean isXffEnabled() {
        return config.dynamic.http.xff.enabled;
    }
    @Override
    public String getInternalProxies() {
        return config.dynamic.http.xff.internalProxies;
    }

    @Override
    public String getRemoteIpHeader() {
        return config.dynamic.http.xff.remoteIpHeader;
    }

    @Override
    public boolean isRestAuthDisabled() {
        return config.dynamic.disable_rest_auth;
    }
    @Override
    public boolean isInterTransportAuthDisabled() {
        return config.dynamic.disable_intertransport_auth;
    }
    @Override
    public boolean isRespectRequestIndicesEnabled() {
        return config.dynamic.respect_request_indices_options;
    }
    @Override
    public String getKibanaServerUsername() {
        return config.dynamic.kibana.server_username;
    }
    @Override
    public String getKibanaIndexname() {
        return config.dynamic.kibana.index;
    }
    @Override
    public boolean isKibanaMultitenancyEnabled() {
        return config.dynamic.kibana.multitenancy_enabled;
    }
    @Override
    public boolean isDnfofEnabled() {
        return config.dynamic.do_not_fail_on_forbidden;
    }
    @Override
    public boolean isMultiRolespanEnabled() {
        return config.dynamic.multi_rolespan_enabled;
    }
    @Override
    public String getFilteredAliasMode() {
        return config.dynamic.filtered_alias_mode;
    }

    @Override
    public String getHostsResolverMode() {
        return config.dynamic.hosts_resolver_mode;
    }
    
    @Override
    public boolean isDnfofForEmptyResultsEnabled() {
        return config.dynamic.do_not_fail_on_forbidden_empty;
    }
    
    @Override
    public List<AuthFailureListener> getIpAuthFailureListeners() {
        return Collections.unmodifiableList(ipAuthFailureListeners);
    }
    
    @Override
    public Multimap<String, AuthFailureListener> getAuthBackendFailureListeners() {
        return Multimaps.unmodifiableMultimap(authBackendFailureListeners);
    }
    
    @Override
    public List<ClientBlockRegistry<InetAddress>> getIpClientBlockRegistries() {
        return Collections.unmodifiableList(ipClientBlockRegistries);
    }
    
    @Override
    public Multimap<String, ClientBlockRegistry<String>> getAuthBackendClientBlockRegistries() {
        return Multimaps.unmodifiableMultimap(authBackendClientBlockRegistries);
    }
    
    
    private void buildAAA() {
        
        final SortedSet<AuthDomain> restAuthDomains0 = new TreeSet<>();
        final Set<AuthorizationBackend> restAuthorizers0 = new HashSet<>();
        final SortedSet<AuthDomain> transportAuthDomains0 = new TreeSet<>();
        final Set<AuthorizationBackend> transportAuthorizers0 = new HashSet<>();
        final List<Destroyable> destroyableComponents0 = new LinkedList<>();
        final List<AuthFailureListener> ipAuthFailureListeners0 = new ArrayList<>();
        final Multimap<String, AuthFailureListener> authBackendFailureListeners0 = ArrayListMultimap.create();
        final List<ClientBlockRegistry<InetAddress>> ipClientBlockRegistries0 = new ArrayList<>();
        final Multimap<String, ClientBlockRegistry<String>> authBackendClientBlockRegistries0 = ArrayListMultimap.create();

        final Authz authzDyn = config.dynamic.authz;

        for (final Entry<String, AuthzDomain> ad : authzDyn.getDomains().entrySet()) {
            final boolean httpEnabled = ad.getValue().http_enabled;
            final boolean transportEnabled = ad.getValue().transport_enabled;


            if (httpEnabled || transportEnabled) {
                try {

                    final String authzBackendClazz = ad.getValue().authorization_backend.type;
                    final AuthorizationBackend authorizationBackend;
                    
                    if(authzBackendClazz.equals(InternalAuthenticationBackend.class.getName()) //NOSONAR
                            || authzBackendClazz.equals("internal")
                            || authzBackendClazz.equals("intern")) {
                        authorizationBackend = iab;
                        ReflectionHelper.addLoadedModule(InternalAuthenticationBackend.class);
                    } else {
                        authorizationBackend = newInstance(
                                authzBackendClazz,"z",
                                Settings.builder()
                                .put(esSettings)
                                //.putProperties(ads.getAsStringMap(DotPath.of("authorization_backend.config")), DynamicConfiguration.checkKeyFunction()).build(), configPath);
                                .put(Settings.builder().loadFromSource(ad.getValue().authorization_backend.configAsJson(), XContentType.JSON).build()).build()
                                , configPath);
                    }
                    
                    if (httpEnabled) {
                        restAuthorizers0.add(authorizationBackend);
                    }

                    if (transportEnabled) {
                        transportAuthorizers0.add(authorizationBackend);
                    }
                    
                    if (authorizationBackend instanceof Destroyable) {
                        destroyableComponents0.add((Destroyable) authorizationBackend);
                    }
                } catch (final Exception e) {
                    log.error("Unable to initialize AuthorizationBackend {} due to {}", ad, e.toString(),e);
                }
            }
        }

        final Authc authcDyn = config.dynamic.authc;

        for (final Entry<String, AuthcDomain> ad : authcDyn.getDomains().entrySet()) {
            final boolean httpEnabled = ad.getValue().http_enabled;
            final boolean transportEnabled = ad.getValue().transport_enabled;

            if (httpEnabled || transportEnabled) {
                try {
                    AuthenticationBackend authenticationBackend;
                    final String authBackendClazz = ad.getValue().authentication_backend.type;
                    if(authBackendClazz.equals(InternalAuthenticationBackend.class.getName()) //NOSONAR
                            || authBackendClazz.equals("internal")
                            || authBackendClazz.equals("intern")) {
                        authenticationBackend = iab;
                        ReflectionHelper.addLoadedModule(InternalAuthenticationBackend.class);
                    } else {
                        authenticationBackend = newInstance(
                                authBackendClazz,"c",
                                Settings.builder()
                                .put(esSettings)
                                //.putProperties(ads.getAsStringMap(DotPath.of("authentication_backend.config")), DynamicConfiguration.checkKeyFunction()).build()
                                .put(Settings.builder().loadFromSource(ad.getValue().authentication_backend.configAsJson(), XContentType.JSON).build()).build()
                                , configPath);
                    }

                    String httpAuthenticatorType = ad.getValue().http_authenticator.type; //no default
                    HTTPAuthenticator httpAuthenticator = httpAuthenticatorType==null?null:  (HTTPAuthenticator) newInstance(httpAuthenticatorType,"h",
                            Settings.builder().put(esSettings)
                            //.putProperties(ads.getAsStringMap(DotPath.of("http_authenticator.config")), DynamicConfiguration.checkKeyFunction()).build(), 
                            .put(Settings.builder().loadFromSource(ad.getValue().http_authenticator.configAsJson(), XContentType.JSON).build()).build()

                            , configPath);

                    final AuthDomain _ad = new AuthDomain(authenticationBackend, httpAuthenticator,
                            ad.getValue().http_authenticator.challenge, ad.getValue().order);

                    if (httpEnabled && _ad.getHttpAuthenticator() != null) {
                        restAuthDomains0.add(_ad);
                    }

                    if (transportEnabled) {
                        transportAuthDomains0.add(_ad);
                    }
                    
                    if (httpAuthenticator instanceof Destroyable) {
                        destroyableComponents0.add((Destroyable) httpAuthenticator);
                    }
                    
                    if (authenticationBackend instanceof Destroyable) {
                        destroyableComponents0.add((Destroyable) authenticationBackend);
                    }
                    
                } catch (final Exception e) {
                    log.error("Unable to initialize auth domain {} due to {}", ad, e.toString(), e);
                }

            }
        }

        List<Destroyable> originalDestroyableComponents = destroyableComponents;
        
        restAuthDomains = Collections.unmodifiableSortedSet(restAuthDomains0);
        transportAuthDomains = Collections.unmodifiableSortedSet(transportAuthDomains0);
        restAuthorizers = Collections.unmodifiableSet(restAuthorizers0);
        transportAuthorizers = Collections.unmodifiableSet(transportAuthorizers0);
        
        destroyableComponents = Collections.unmodifiableList(destroyableComponents0);
        
        if(originalDestroyableComponents != null) {
            destroyDestroyables(originalDestroyableComponents);
        }
        
        originalDestroyableComponents = null;

        createAuthFailureListeners(ipAuthFailureListeners0,
                authBackendFailureListeners0, ipClientBlockRegistries0, authBackendClientBlockRegistries0, destroyableComponents0);
        
        ipAuthFailureListeners = Collections.unmodifiableList(ipAuthFailureListeners0);
        ipClientBlockRegistries = Collections.unmodifiableList(ipClientBlockRegistries0);
        authBackendClientBlockRegistries = Multimaps.unmodifiableMultimap(authBackendClientBlockRegistries0);
        authBackendFailureListeners = Multimaps.unmodifiableMultimap(authBackendFailureListeners0);

    }

    private void destroyDestroyables(List<Destroyable> destroyableComponents) {
        for (Destroyable destroyable : destroyableComponents) {
            try {
                destroyable.destroy();
            } catch (Exception e) {
                log.error("Error while destroying " + destroyable, e);
            }
        }
    }
    
    private <T> T newInstance(final String clazzOrShortcut, String type, final Settings settings, final Path configPath) {

        String clazz = clazzOrShortcut;
        boolean isEnterprise = false;

        if(authImplMap.containsKey(clazz+"_"+type)) {
            clazz = authImplMap.get(clazz+"_"+type);
        } else {
            isEnterprise = true;
        }

        if(ReflectionHelper.isAdvancedModuleAAAModule(clazz)) {
            isEnterprise = true;
        }

        return ReflectionHelper.instantiateAAA(clazz, settings, configPath, isEnterprise);
    }
    
    private String translateShortcutToClassName(final String clazzOrShortcut, final String type) {

        if (authImplMap.containsKey(clazzOrShortcut + "_" + type)) {
            return authImplMap.get(clazzOrShortcut + "_" + type);
        } else {
            return clazzOrShortcut;
        }
    }
    
    private void createAuthFailureListeners(List<AuthFailureListener> ipAuthFailureListeners,
            Multimap<String, AuthFailureListener> authBackendFailureListeners, List<ClientBlockRegistry<InetAddress>> ipClientBlockRegistries,
            Multimap<String, ClientBlockRegistry<String>> authBackendUserClientBlockRegistries, List<Destroyable> destroyableComponents0) {

        for (Entry<String, ConfigV7.AuthFailureListener> entry : config.dynamic.auth_failure_listeners.getListeners().entrySet()) {
            
            Settings entrySettings = Settings.builder()
            .put(esSettings)
            .put(Settings.builder().loadFromSource(entry.getValue().asJson(), XContentType.JSON).build()).build();
            
            String type = entry.getValue().type;
            String authenticationBackend = entry.getValue().authentication_backend;

            AuthFailureListener authFailureListener = newInstance(type, "authFailureListener", entrySettings, configPath);

            if (Strings.isNullOrEmpty(authenticationBackend)) {
                ipAuthFailureListeners.add(authFailureListener);

                if (authFailureListener instanceof ClientBlockRegistry) {
                    if (InetAddress.class.isAssignableFrom(((ClientBlockRegistry<?>) authFailureListener).getClientIdType())) {
                        @SuppressWarnings("unchecked")
                        ClientBlockRegistry<InetAddress> clientBlockRegistry = (ClientBlockRegistry<InetAddress>) authFailureListener;

                        ipClientBlockRegistries.add(clientBlockRegistry);
                    } else {
                        log.error("Illegal ClientIdType for AuthFailureListener" + entry.getKey() + ": "
                                + ((ClientBlockRegistry<?>) authFailureListener).getClientIdType() + "; must be InetAddress.");
                    }
                }

            } else {

                authenticationBackend = translateShortcutToClassName(authenticationBackend, "c");

                authBackendFailureListeners.put(authenticationBackend, authFailureListener);

                if (authFailureListener instanceof ClientBlockRegistry) {
                    if (String.class.isAssignableFrom(((ClientBlockRegistry<?>) authFailureListener).getClientIdType())) {
                        @SuppressWarnings("unchecked")
                        ClientBlockRegistry<String> clientBlockRegistry = (ClientBlockRegistry<String>) authFailureListener;

                        authBackendUserClientBlockRegistries.put(authenticationBackend, clientBlockRegistry);
                    } else {
                        log.error("Illegal ClientIdType for AuthFailureListener" + entry.getKey() + ": "
                                + ((ClientBlockRegistry<?>) authFailureListener).getClientIdType() + "; must be InetAddress.");
                    }
                }
            }

            if (authFailureListener instanceof Destroyable) {
                destroyableComponents0.add((Destroyable) authFailureListener);
            }
        }

    }
}
