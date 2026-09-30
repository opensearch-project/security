/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.GatingResourceResolver;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("unchecked") // action listener mock
public class ResourceAccessEvaluatorTest {

    @Mock
    private ResourceAccessHandler resourceAccessHandler;
    @Mock
    private ResourcePluginInfo resourcePluginInfo;

    @Mock
    private PrivilegesEvaluationContext context;

    @Mock
    private OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting;
    @Mock
    private OpensearchDynamicSetting<List<String>> protectedResourceTypesSetting;

    private ThreadContext threadContext;
    private ResourceAccessEvaluator evaluator;

    private static final String IDX = "resource-index";
    private static final String REQUEST_TYPE = "alerting-comment";
    private static final String GATING_TYPE = "monitor";
    private static final String GATING_ID = "monitor-1";

    @Before
    public void setup() {
        threadContext = new ThreadContext(Settings.EMPTY);
        evaluator = new ResourceAccessEvaluator(
            resourcePluginInfo,
            resourceAccessHandler,
            resourceSharingEnabledSetting,
            protectedResourceTypesSetting
        );
    }

    private void stubAuthenticatedUser() {
        User user = new User("test-user");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, user);
        threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, user);
    }

    private void assertEvaluateAsync(boolean hasPermission, boolean expectedAllowed) {
        stubAuthenticatedUser();
        IndexRequest req = new IndexRequest(IDX).id("anyId");

        // TODO check to see if type can be something other than indices
        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(hasPermission);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq("anyId"), eq("indices"), eq("read"), any());

        ActionListener<PrivilegesEvaluatorResponse> callback = mock(ActionListener.class);

        evaluator.evaluateAsync(req, "read", callback);

        ArgumentCaptor<PrivilegesEvaluatorResponse> captor = ArgumentCaptor.forClass(PrivilegesEvaluatorResponse.class);
        verify(callback).onResponse(captor.capture());

        PrivilegesEvaluatorResponse out = captor.getValue();
        assertThat(out.isAllowed(), equalTo(expectedAllowed));
    }

    @Test
    public void testEvaluateAsync_whenHasPermissionTrue_thenAllowed() {
        assertEvaluateAsync(true, true);
    }

    @Test
    public void testEvaluateAsync_whenHasPermissionFalse_thenNotAllowed() {
        assertEvaluateAsync(false, false);
    }

    /**
     * A request whose access is governed by another resource: the evaluator asks the plugin's resolver for that resource
     * and authorizes it, of the gating type, rather than the one the request names.
     */
    @Test
    public void testEvaluateAsync_gatedRequest_authorizesTheResolvedResource() {
        stubAuthenticatedUser();
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(GATING_ID, null));

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(true);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(GATING_ID), eq(GATING_TYPE), eq("read"), any());

        assertGatedEvaluation(true);
    }

    @Test
    public void testEvaluateAsync_gatedRequest_deniedWhenTheResolvedResourceDoesNotGrantTheAction() {
        stubAuthenticatedUser();
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(GATING_ID, null));

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(false);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(GATING_ID), eq(GATING_TYPE), eq("read"), any());

        assertGatedEvaluation(false);
    }

    @Test
    public void testEvaluateAsync_gatedRequest_deniedWhenNothingResolves() {
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(null, null));

        assertGatedEvaluation(false);
        verify(resourceAccessHandler, never()).hasPermission(anyString(), anyString(), anyString(), any());
    }

    @Test
    public void testEvaluateAsync_gatedRequest_deniedWhenResolutionFails() {
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(null, new RuntimeException("boom")));

        assertGatedEvaluation(false);
        verify(resourceAccessHandler, never()).hasPermission(anyString(), anyString(), anyString(), any());
    }

    /**
     * The request's own index is not a resource index and the document it names need not exist, so the evaluator takes
     * the request on the strength of the gating type being protected. {@code getResourceIndicesForProtectedTypes} is
     * deliberately not stubbed here: it must not be consulted.
     */
    @Test
    public void testShouldEvaluate_gatedRequestWhenGatingTypeIsProtected() {
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(true);
        when(protectedResourceTypesSetting.getDynamicSettingValue()).thenReturn(List.of(GATING_TYPE));
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(GATING_ID, null));

        assertThat(evaluator.shouldEvaluate(new GatedRequest()), equalTo(true));
    }

    @Test
    public void testShouldEvaluate_gatedRequestWhenGatingTypeIsNotProtected() {
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(true);
        when(protectedResourceTypesSetting.getDynamicSettingValue()).thenReturn(List.of("some-other-type"));
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(GATING_ID, null));

        assertThat(evaluator.shouldEvaluate(new GatedRequest()), equalTo(false));
    }

    private void assertGatedEvaluation(boolean expectedAllowed) {
        ActionListener<PrivilegesEvaluatorResponse> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(new GatedRequest(), "read", callback);

        ArgumentCaptor<PrivilegesEvaluatorResponse> captor = ArgumentCaptor.forClass(PrivilegesEvaluatorResponse.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().isAllowed(), equalTo(expectedAllowed));
    }

    private GatingResourceResolver resolverReturning(String gatingId, Exception failure) {
        return new GatingResourceResolver() {
            @Override
            public String requestType() {
                return REQUEST_TYPE;
            }

            @Override
            public String gatingResourceType() {
                return GATING_TYPE;
            }

            @Override
            public void resolveGatingResourceId(DocRequest request, ActionListener<String> listener) {
                if (failure != null) {
                    listener.onFailure(failure);
                } else {
                    listener.onResponse(gatingId);
                }
            }
        };
    }

    /**
     * A request naming a document of its own, whose access is governed by a resource of another type.
     */
    private static class GatedRequest extends ActionRequest implements DocRequest {
        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public String type() {
            return REQUEST_TYPE;
        }

        @Override
        public String index() {
            return "some-other-index";
        }

        @Override
        public String id() {
            return "comment-1";
        }
    }

}
