/*
 *   Copyright OpenSearch Contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

package org.opensearch.security.auth;

import java.util.ArrayList;
import java.util.List;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.commons.ConfigConstants;
import org.opensearch.commons.authuser.User;
import org.opensearch.rule.SecurityAttribute;
import org.opensearch.rule.attribute_extractor.AttributeExtractor;
import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.threadpool.ThreadPool;

/**
 * This class extracts the principal (username and roles) from a request
 */
public class PrincipalExtractor implements AttributeExtractor<String> {
    private final ThreadPool threadPool;

    public PrincipalExtractor(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    @Override
    public Attribute getAttribute() {
        return SecurityAttribute.PRINCIPAL;
    }

    @Override
    public Iterable<String> extract() {
        ThreadContext threadContext = threadPool.getThreadContext();
        String userStr = threadContext.getTransient(ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT);
        List<String> principals = new ArrayList<>();
        if (userStr != null && !userStr.isEmpty()) {
            User user = User.parse(userStr);
            principals.add(String.join("_", SecurityAttribute.USERNAME, user.getName()));
            for (String role : user.getRoles()) {
                principals.add(String.join("_", SecurityAttribute.ROLE, role));
            }
        }
        return principals;
    }

    @Override
    public CombinationStyle getCombinationStyle() {
        return CombinationStyle.OR;
    }
}
