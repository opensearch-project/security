/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.support.ConfigConstants;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("unchecked") // action listener mock
public class ResourceAccessEvaluatorTest {

    @Mock
    private ResourceAccessHandler resourceAccessHandler;

    @Mock
    private PrivilegesEvaluationContext context;

    private ThreadContext threadContext;
    private ResourceAccessEvaluator evaluator;

    private static final String IDX = "resource-index";

    @Before
    public void setup() {
        Settings settings = Settings.builder().put(ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED, true).build();
        threadContext = new ThreadContext(Settings.EMPTY);
        evaluator = new ResourceAccessEvaluator(Collections.singleton(IDX), settings, resourceAccessHandler);
    }

    private void stubAuthenticatedUser() {
        UserSubjectImpl subject = mock(UserSubjectImpl.class);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
        threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
    }

    private void assertEvaluateAsync(boolean hasPermission, boolean expectedAllowed) {
        stubAuthenticatedUser();
        IndexRequest req = new IndexRequest(IDX).id("anyId");

        // TODO check to see if type can be something other than indices
        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(4);
            listener.onResponse(hasPermission);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq("anyId"), eq("indices"), eq("read"), any(), any());

        ActionListener<PrivilegesEvaluatorResponse> callback = mock(ActionListener.class);

        evaluator.evaluateAsync(req, "read", context, callback);

        ArgumentCaptor<PrivilegesEvaluatorResponse> captor = ArgumentCaptor.forClass(PrivilegesEvaluatorResponse.class);
        verify(callback).onResponse(captor.capture());

        PrivilegesEvaluatorResponse out = captor.getValue();
        assertThat(out.allowed, equalTo(expectedAllowed));
        assertThat(out.isComplete(), equalTo(true));
    }

    @Test
    public void testEvaluateAsync_whenHasPermissionTrue_thenAllowed() {
        assertEvaluateAsync(true, true);
    }

    @Test
    public void testEvaluateAsync_whenHasPermissionFalse_thenNotAllowed() {
        assertEvaluateAsync(false, false);
    }

}
