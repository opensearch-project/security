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
import java.util.Arrays;
import java.util.List;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.rule.attribute_extractor.AttributeExtractor;
import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.security.support.ConfigConstants;
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
        return PrincipalAttribute.PRINCIPAL;
    }

    @Override
    public Iterable<String> extract() {
        ThreadContext threadContext = threadPool.getThreadContext();
        String userStr = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT);
        UserPrincipalInfo userPrincipalInfo = parse(userStr);
        List<String> principals = new ArrayList<>();
        if (userPrincipalInfo != null) {
            principals.add(String.join("|", PrincipalAttribute.USERNAME, userPrincipalInfo.getUserName()));
            for (String role : userPrincipalInfo.getRoles()) {
                principals.add(String.join("|", PrincipalAttribute.ROLE, role));
            }
        }
        return principals;
    }

    /**
     * Parses a user string into {@link UserPrincipalInfo}.
     * User String format must be pipe separated as : user_name|backendrole1,backendrole2|roles1,role2|tenant|tenantAccess|base64-encoded(serialized(custom atttributes))
     * @param userString
     */
    @SuppressWarnings("unchecked")
    private UserPrincipalInfo parse(final String userString) {
        if (Strings.isNullOrEmpty(userString)) {
            return null;
        }

        String[] strs = userString.split("(?<!\\\\)\\|");
        if ((strs.length == 0) || (Strings.isNullOrEmpty(strs[0]))) {
            return null;
        }

        String userName = unescapePipe(strs[0].trim());
        List<String> roles = new ArrayList<>();

        if ((strs.length > 2) && !Strings.isNullOrEmpty(strs[2])) {
            roles.addAll(Arrays.stream(strs[2].split(",")).map(this::unescapePipe).toList());
        }

        return new UserPrincipalInfo(userName, roles);
    }

    private String unescapePipe(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\|", "|");
    }

    @Override
    public LogicalOperator getLogicalOperator() {
        return LogicalOperator.OR;
    }

    /**
     * Holds parsed user information (username and roles).
     */
    public static class UserPrincipalInfo {
        private final String userName;
        private final List<String> roles;

        public UserPrincipalInfo(String userName, List<String> roles) {
            this.userName = userName;
            this.roles = List.copyOf(roles);
        }

        public String getUserName() {
            return userName;
        }

        public List<String> getRoles() {
            return roles;
        }
    }
}
