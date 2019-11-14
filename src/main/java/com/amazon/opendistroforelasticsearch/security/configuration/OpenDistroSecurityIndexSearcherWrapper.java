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

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.io.IOException;
import java.util.Collection;
import java.util.Set;

import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigFactory;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.InternalUsersModel;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.DirectoryReader;
import org.elasticsearch.common.CheckedFunction;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexService;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HeaderHelper;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class OpenDistroSecurityIndexSearcherWrapper implements CheckedFunction<DirectoryReader, DirectoryReader, IOException>, DynamicConfigFactory.DCFListener  {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final ThreadContext threadContext;
    protected final Index index;
    protected final String opendistrosecurityIndex;
    private final AdminDNs adminDns;
    private ConfigModel configModel;
    private final PrivilegesEvaluator evaluator;
    private final Collection<String> indexPatterns;
    private final Collection<String> allowedRoles;
    private final Boolean protectedIndexEnabled;

    //constructor is called per index, so avoid costly operations here
    public OpenDistroSecurityIndexSearcherWrapper(final IndexService indexService, final Settings settings, final AdminDNs adminDNs, final PrivilegesEvaluator evaluator) {
        index = indexService.index();
        threadContext = indexService.getThreadPool().getThreadContext();
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.evaluator = evaluator;
        this.adminDns = adminDNs;
        this.indexPatterns = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY);
        this.allowedRoles = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY);
        this.protectedIndexEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT);
    }

    @Override
    public void onChanged(ConfigModel cm, DynamicConfigModel dcm, InternalUsersModel ium) {
        this.configModel = cm;
    }

    @Override
    public final DirectoryReader apply(DirectoryReader reader) throws IOException {

        if (isSecurityIndexRequest() && !isAdminAuthenticatedOrInternalRequest()) {
            return new EmptyFilterLeafReader.EmptyDirectoryReader(reader);
        }
        if (protectedIndexEnabled && isBlockedIndexRequest() && !isPermittedOnIndex()) {
            return new EmptyFilterLeafReader.EmptyDirectoryReader(reader);
        }

        return dlsFlsWrap(reader, isAdminAuthenticatedOrInternalRequest());
    }

    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader, boolean isAdmin) throws IOException {
        return reader;
    }

    protected final boolean isAdminAuthenticatedOrInternalRequest() {

        final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        if (user != null && adminDns.isAdmin(user)) {
            return true;
        }

        if ("true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER))) {
            return true;
        }

        return false;
    }

    protected final boolean isSecurityIndexRequest() {
        return index.getName().equals(opendistrosecurityIndex);
    }

    protected final boolean isBlockedIndexRequest() {
        return WildcardMatcher.matchAny(indexPatterns, index.getName());
    }

    protected final boolean isPermittedOnIndex() {
        final TransportAddress caller = (TransportAddress) this.threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (caller == null || user == null) {
            return false;
        }
        final Set<String> securityRoles = evaluator.mapRoles(user, caller);
        if (WildcardMatcher.matchAny(allowedRoles, securityRoles)) {
            return true;
        }
        return false;
    }
}
