/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.saml;

import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.joda.time.DateTime;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.RefreshableMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;

import com.amazon.dlic.auth.http.jwt.keybyoidc.AuthenticatorUnavailableException;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

public class Saml2SettingsProvider {
    protected final static Logger log = LogManager.getLogger(Saml2SettingsProvider.class);

    private final Settings opensearchSettings;
    private final MetadataResolver metadataResolver;
    private final String idpEntityId;
    private final PrivateKey spSignaturePrivateKey;
    private Saml2Settings cachedSaml2Settings;
    private DateTime metadataUpdateTime;

    Saml2SettingsProvider(Settings opensearchSettings, MetadataResolver metadataResolver, PrivateKey spSignaturePrivateKey) {
        this.opensearchSettings = opensearchSettings;
        this.metadataResolver = metadataResolver;
        this.idpEntityId = opensearchSettings.get("idp.entity_id");
        this.spSignaturePrivateKey = spSignaturePrivateKey;
    }

    Saml2Settings get() throws SamlConfigException {
        try {
            HashMap<String, Object> configProperties = new HashMap<>();

            EntityDescriptor entityDescriptor = this.metadataResolver
                    .resolveSingle(new CriteriaSet(new EntityIdCriterion(this.idpEntityId)));

            if (entityDescriptor == null) {
                throw new SamlConfigException("Could not find entity descriptor for " + this.idpEntityId);
            }

            IDPSSODescriptor idpSsoDescriptor = entityDescriptor
                    .getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");

            if (idpSsoDescriptor == null) {
                throw new SamlConfigException("Could not find IDPSSODescriptor supporting SAML 2.0 in "
                        + this.idpEntityId + "; role descriptors: " + entityDescriptor.getRoleDescriptors());
            }

            initIdpEndpoints(idpSsoDescriptor, configProperties);
            initIdpCerts(idpSsoDescriptor, configProperties);

            initSpEndpoints(configProperties);

            initMisc(configProperties);

            SettingsBuilder settingsBuilder = new SettingsBuilder();

            // TODO allow overriding of IdP metadata?
            settingsBuilder.fromValues(configProperties);
            settingsBuilder.fromValues(new SamlSettingsMap(this.opensearchSettings));
            SpecialPermission.check();
            return AccessController.doPrivileged((PrivilegedAction<Saml2Settings>) () -> settingsBuilder.build());
        } catch (ResolverException e) {
            throw new AuthenticatorUnavailableException(e);
        }
    }

    Saml2Settings getCached() throws SamlConfigException {
        DateTime tempLastUpdate = null;

        if (this.metadataResolver instanceof RefreshableMetadataResolver && this.isUpdateRequired()) {
            this.cachedSaml2Settings = null;
            tempLastUpdate = ((RefreshableMetadataResolver) this.metadataResolver).getLastUpdate();
        }

        if (this.cachedSaml2Settings == null) {
            this.cachedSaml2Settings = this.get();
            this.metadataUpdateTime = tempLastUpdate;
        }

        return this.cachedSaml2Settings;
    }

    private boolean isUpdateRequired() {
        RefreshableMetadataResolver refreshableMetadataResolver = (RefreshableMetadataResolver) this.metadataResolver;

        if (this.cachedSaml2Settings == null || this.metadataUpdateTime == null
                || refreshableMetadataResolver.getLastUpdate() == null) {
            return true;
        }

        if (refreshableMetadataResolver.getLastUpdate().isAfter(this.metadataUpdateTime)) {
            return true;
        } else {
            return false;
        }
    }

    private void initMisc(HashMap<String, Object> configProperties) {
        configProperties.put(SettingsBuilder.STRICT_PROPERTY_KEY, true);
        configProperties.put(SettingsBuilder.SECURITY_REJECT_UNSOLICITED_RESPONSES_WITH_INRESPONSETO, true);
        configProperties.put(SettingsBuilder.SP_PRIVATEKEY_PROPERTY_KEY, this.spSignaturePrivateKey);
    }

    private void initSpEndpoints(HashMap<String, Object> configProperties) {
        configProperties.put(SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY,
                this.buildAssertionConsumerEndpoint(this.opensearchSettings.get("kibana_url")));
        configProperties.put(SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY,
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        configProperties.put(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, this.opensearchSettings.get("sp.entity_id"));
    }

    private void initIdpEndpoints(IDPSSODescriptor idpSsoDescriptor, HashMap<String, Object> configProperties)
            throws SamlConfigException {
        SingleSignOnService singleSignOnService = this.findSingleSignOnService(idpSsoDescriptor,
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        configProperties.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY,
                singleSignOnService.getLocation());
        configProperties.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY,
                singleSignOnService.getBinding());
        configProperties.put(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY, this.opensearchSettings.get("idp.entity_id"));

        SingleLogoutService singleLogoutService = this.findSingleLogoutService(idpSsoDescriptor,
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        if (singleLogoutService != null) {
            configProperties.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY,
                    singleLogoutService.getLocation());
            configProperties.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY,
                    singleLogoutService.getBinding());
        } else {
            log.warn(
                    "The IdP does not provide a Single Logout Service. In order to ensure that users have to re-enter their password after logging out, OpenSearch Security will issue all SAML authentication requests with a mandatory password input (ForceAuthn=true)");
        }
    }

    private void initIdpCerts(IDPSSODescriptor idpSsoDescriptor, HashMap<String, Object> configProperties) {
        int i = 0;

        for (KeyDescriptor keyDescriptor : idpSsoDescriptor.getKeyDescriptors()) {
            if (UsageType.SIGNING.equals(keyDescriptor.getUse())
                    || UsageType.UNSPECIFIED.equals(keyDescriptor.getUse())) {
                for (X509Data x509data : keyDescriptor.getKeyInfo().getX509Datas()) {
                    for (X509Certificate x509Certificate : x509data.getX509Certificates()) {
                        configProperties.put(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + (i++),
                                x509Certificate.getValue());
                    }
                }
            }
        }
    }

    private SingleSignOnService findSingleSignOnService(IDPSSODescriptor idpSsoDescriptor, String binding)
            throws SamlConfigException {
        for (SingleSignOnService singleSignOnService : idpSsoDescriptor.getSingleSignOnServices()) {
            if (binding.equals(singleSignOnService.getBinding())) {
                return singleSignOnService;
            }
        }

        throw new SamlConfigException("Could not find SingleSignOnService endpoint for binding " + binding
                + "; available services: " + idpSsoDescriptor.getSingleSignOnServices());
    }

    private SingleLogoutService findSingleLogoutService(IDPSSODescriptor idpSsoDescriptor, String binding)
            throws SamlConfigException {
        for (SingleLogoutService singleLogoutService : idpSsoDescriptor.getSingleLogoutServices()) {
            if (binding.equals(singleLogoutService.getBinding())) {
                return singleLogoutService;
            }
        }

        return null;
    }

    private String buildAssertionConsumerEndpoint(String dashboardsRoot) {

        if (dashboardsRoot.endsWith("/")) {
            return dashboardsRoot + "_opendistro/_security/saml/acs";
        } else {
            return dashboardsRoot + "/_opendistro/_security/saml/acs";
        }
    }

    static class SamlSettingsMap implements Map<String, Object> {

        private static final String KEY_PREFIX = "onelogin.saml2.";

        private Settings settings;

        SamlSettingsMap(Settings settings) {
            this.settings = settings.getAsSettings("validator");
        }

        @Override
        public int size() {
            return this.settings.size();
        }

        @Override
        public boolean isEmpty() {
            return this.settings.isEmpty();
        }

        @Override
        public boolean containsKey(Object key) {
            return this.settings.hasValue(this.adaptKey(key));
        }

        @Override
        public boolean containsValue(Object value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object get(Object key) {
            return this.settings.get(this.adaptKey(key));
        }

        @Override
        public Object put(String key, Object value) {
            throw new UnsupportedOperationException();

        }

        @Override
        public Object remove(Object key) {
            throw new UnsupportedOperationException();

        }

        @Override
        public void putAll(Map<? extends String, ? extends Object> m) {
            throw new UnsupportedOperationException();

        }

        @Override
        public void clear() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> keySet() {
            return this.settings.keySet().stream().map((s) -> KEY_PREFIX + s).collect(Collectors.toSet());
        }

        @Override
        public Collection<Object> values() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<Entry<String, Object>> entrySet() {
            Set<Entry<String, Object>> result = new HashSet<>();

            for (String key : this.settings.keySet()) {
                result.add(new AbstractMap.SimpleEntry<String, Object>(KEY_PREFIX + key, this.settings.get(key)));
            }

            return result;
        }

        private String adaptKey(Object keyObject) {
            if (keyObject == null) {
                return null;
            }

            String key = String.valueOf(keyObject);

            if (key.startsWith(KEY_PREFIX)) {
                return key.substring(KEY_PREFIX.length());
            } else {
                return key;
            }
        }
    }
}
