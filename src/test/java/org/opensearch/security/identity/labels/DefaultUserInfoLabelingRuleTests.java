/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.identity.labels;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.util.HashMap;
import java.util.Map;

public class DefaultUserInfoLabelingRuleTests extends OpenSearchTestCase {
    private DefaultUserInfoLabelingRule defaultUserInfoLabelingRule;
    private ThreadContext threadContext;
    private SearchRequest searchRequest;

    @Before
    public void setUpVariables() {
        defaultUserInfoLabelingRule = new DefaultUserInfoLabelingRule();
        threadContext = new ThreadContext(Settings.EMPTY);
        searchRequest = new SearchRequest();
    }

    public void testGetUserInfoFromThreadContext() {
        threadContext.putTransient("_opendistro_security_user_info", "user1|role1,role2|group1,group2|tenant1");
        threadContext.putTransient("_opendistro_security_remote_address", "127.0.0.1");
        Map<String, String> expectedUserInfoMap = new HashMap<>();
        expectedUserInfoMap.put(DefaultUserInfoLabelingRule.REMOTE_ADDRESS, "127.0.0.1");
        expectedUserInfoMap.put(DefaultUserInfoLabelingRule.USER_NAME, "user1");
        expectedUserInfoMap.put(DefaultUserInfoLabelingRule.USER_SECURITY_ROLES, "role1,role2");
        expectedUserInfoMap.put(DefaultUserInfoLabelingRule.USER_ROLES, "group1,group2");
        expectedUserInfoMap.put(DefaultUserInfoLabelingRule.USER_TENANT, "tenant1");
        Map<String, String> actualUserInfoMap = defaultUserInfoLabelingRule.evaluate(threadContext, searchRequest);
        assertEquals(expectedUserInfoMap, actualUserInfoMap);
    }

    public void testGetPartialInfoFromThreadContext() {
        threadContext.putTransient("_opendistro_security_remote_address", "127.0.0.1");
        Map<String, String> expectedUserInfoMap = new HashMap<>();
        expectedUserInfoMap.put(DefaultUserInfoLabelingRule.REMOTE_ADDRESS, "127.0.0.1");
        Map<String, String> actualUserInfoMap = defaultUserInfoLabelingRule.evaluate(threadContext, searchRequest);
        assertEquals(expectedUserInfoMap, actualUserInfoMap);
    }

    public void testGetUserInfoFromThreadContext_EmptyUserInfo() {
        Map<String, String> actualUserInfoMap = defaultUserInfoLabelingRule.evaluate(threadContext, searchRequest);
        assertTrue(actualUserInfoMap.isEmpty());
    }

    public void testGetUserInfoFromThreadContext_NullThreadContext() {
        Map<String, String> userInfoMap = defaultUserInfoLabelingRule.evaluate(null, searchRequest);
        assertTrue(userInfoMap.isEmpty());
    }
}
