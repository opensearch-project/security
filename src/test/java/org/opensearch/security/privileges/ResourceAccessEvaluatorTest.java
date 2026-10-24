/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

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
import org.opensearch.security.spi.resources.MultiResourceRequest;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
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
    private static final String TYPE = "sample-resource";

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

    /**
     * A request implementing neither resource interface.
     */
    private static class PlainRequest extends ActionRequest {
        @Override
        public ActionRequestValidationException validate() {
            return null;
        }
    }

    /**
     * A request naming several resources of one type, as a plugin would implement it.
     */
    private static class MultiIdRequest extends ActionRequest implements MultiResourceRequest {
        private final List<String> ids;

        MultiIdRequest(List<String> ids) {
            this.ids = ids;
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public String type() {
            return TYPE;
        }

        @Override
        public String index() {
            return IDX;
        }

        @Override
        public List<String> ids() {
            return ids;
        }
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
        }).when(resourceAccessHandler).hasPermission(eq(List.of("anyId")), eq("indices"), eq("read"), any());

        ActionListener<ResourceAccessEvaluator.Evaluation> callback = mock(ActionListener.class);

        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

        ArgumentCaptor<ResourceAccessEvaluator.Evaluation> captor = ArgumentCaptor.forClass(ResourceAccessEvaluator.Evaluation.class);
        verify(callback).onResponse(captor.capture());

        ResourceAccessEvaluator.Evaluation out = captor.getValue();
        assertThat(out.response().isAllowed(), equalTo(expectedAllowed));
        // an ordinary request is audited against the resource it names
        assertThat(out.resource().ids(), equalTo(List.of("anyId")));
        assertThat(out.resource().index(), equalTo(IDX));
    }

    @Test
    public void testEvaluateAsync_whenHasPermissionTrue_thenAllowed() {
        assertEvaluateAsync(true, true);
    }

    @Test
    public void testEvaluateAsync_whenHasPermissionFalse_thenNotAllowed() {
        assertEvaluateAsync(false, false);
    }

    @Test
    public void testEvaluateAsync_multiIdRequest_authorizesEveryId() {
        stubAuthenticatedUser();
        MultiIdRequest req = new MultiIdRequest(List.of("id-1", "id-2"));

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(true);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(List.of("id-1", "id-2")), eq(TYPE), eq("read"), any());

        ActionListener<ResourceAccessEvaluator.Evaluation> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

        ArgumentCaptor<ResourceAccessEvaluator.Evaluation> captor = ArgumentCaptor.forClass(ResourceAccessEvaluator.Evaluation.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().response().isAllowed(), equalTo(true));
    }

    @Test
    public void testEvaluateAsync_multiIdRequest_deniedWhenOneIdIsDenied() {
        stubAuthenticatedUser();
        MultiIdRequest req = new MultiIdRequest(List.of("id-1", "id-2"));

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(false);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(List.of("id-1", "id-2")), eq(TYPE), eq("read"), any());

        ActionListener<ResourceAccessEvaluator.Evaluation> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

        ArgumentCaptor<ResourceAccessEvaluator.Evaluation> captor = ArgumentCaptor.forClass(ResourceAccessEvaluator.Evaluation.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().response().isAllowed(), equalTo(false));
    }

    /**
     * A check that fails rather than answering denies the request. Reading a sharing record can fail, and a failure must
     * not read as an allow.
     */
    @Test
    public void testEvaluateAsync_whenTheCheckFails_thenNotAllowed() {
        stubAuthenticatedUser();
        MultiIdRequest req = new MultiIdRequest(List.of("id-1", "id-2"));

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onFailure(new RuntimeException("sharing record read failed"));
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(List.of("id-1", "id-2")), eq(TYPE), eq("read"), any());

        ActionListener<ResourceAccessEvaluator.Evaluation> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

        ArgumentCaptor<ResourceAccessEvaluator.Evaluation> captor = ArgumentCaptor.forClass(ResourceAccessEvaluator.Evaluation.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().response().isAllowed(), equalTo(false));
    }

    @Test
    public void testResourceRequest_singleIdRequest() {
        ResourceAccessEvaluator.ResourceRequest request = ResourceAccessEvaluator.resourceRequest(new IndexRequest(IDX).id("anyId"));
        assertThat(request.index(), equalTo(IDX));
        assertThat(request.ids(), equalTo(List.of("anyId")));
    }

    @Test
    public void testResourceRequest_blankSingleId() {
        assertThat(ResourceAccessEvaluator.resourceRequest(new IndexRequest(IDX)).ids(), equalTo(List.of()));
    }

    @Test
    public void testResourceRequest_dropsBlankIds() {
        ResourceAccessEvaluator.ResourceRequest request = ResourceAccessEvaluator.resourceRequest(
            new MultiIdRequest(Arrays.asList("id-1", "", null, "id-2"))
        );
        assertThat(request.ids(), equalTo(List.of("id-1", "id-2")));
    }

    @Test
    public void testResourceRequest_multiIdRequestDeduplicates() {
        ResourceAccessEvaluator.ResourceRequest request = ResourceAccessEvaluator.resourceRequest(
            new MultiIdRequest(List.of("id-1", "id-2", "id-1"))
        );
        assertThat(request.index(), equalTo(IDX));
        assertThat(request.type(), equalTo(TYPE));
        assertThat(request.ids(), equalTo(List.of("id-1", "id-2")));
    }

    /**
     * A request implementing neither interface names no resource, so there is nothing to normalize.
     */
    @Test
    public void testResourceRequest_requestNamingNoResource() {
        assertThat(ResourceAccessEvaluator.resourceRequest(new PlainRequest()), equalTo(null));
        assertThat(shouldEvaluate(new PlainRequest()), equalTo(false));
    }

    private boolean shouldEvaluate(ActionRequest request) {
        return evaluableResourceRequest(request) != null;
    }

    private ResourceAccessEvaluator.ResourceRequest evaluableResourceRequest(ActionRequest request) {
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(true);
        when(protectedResourceTypesSetting.getDynamicSettingValue()).thenReturn(List.of(TYPE));
        return evaluator.evaluableResourceRequest(request);
    }

    @Test
    public void testShouldEvaluate_multiIdRequestWithIds() {
        when(resourcePluginInfo.getResourceIndicesForProtectedTypes()).thenReturn(Set.of(IDX));
        assertThat(shouldEvaluate(new MultiIdRequest(List.of("id-1", "id-2"))), equalTo(true));
    }

    @Test
    public void testShouldEvaluate_multiIdRequestWithNoIds() {
        assertThat(shouldEvaluate(new MultiIdRequest(List.of())), equalTo(false));
    }

    /**
     * A blank id names no resource, so it is dropped and the real id beside it is still authorized. Disqualifying the
     * whole request instead would hand that real id to the regular evaluator, which is a way past resource evaluation
     * for a caller who holds the action through a role.
     */
    @Test
    public void testShouldEvaluate_multiIdRequestWithBlankIdStillGatesTheRealId() {
        when(resourcePluginInfo.getResourceIndicesForProtectedTypes()).thenReturn(Set.of(IDX));

        ResourceAccessEvaluator.ResourceRequest request = evaluableResourceRequest(new MultiIdRequest(Arrays.asList("id-1", "")));

        assertThat(request, not(equalTo(null)));
        assertThat(request.ids(), equalTo(List.of("id-1")));
    }

    /**
     * Dropping the only id leaves nothing to authorize, which still falls through, as a request meaning "all resources"
     * relies on.
     */
    @Test
    public void testShouldEvaluate_multiIdRequestWithOnlyBlankIds() {
        assertThat(shouldEvaluate(new MultiIdRequest(Arrays.asList("", null))), equalTo(false));
    }

    @Test
    public void testShouldEvaluate_multiIdRequestWithNullIds() {
        assertThat(shouldEvaluate(new MultiIdRequest(null)), equalTo(false));
    }

    @Test
    public void testShouldEvaluate_multiIdRequestOfUnprotectedType() {
        when(resourcePluginInfo.getResourceIndicesForProtectedTypes()).thenReturn(Set.of("some-other-index"));
        assertThat(shouldEvaluate(new MultiIdRequest(List.of("id-1"))), equalTo(false));
    }

    private static final String REQUEST_TYPE = "alerting-comment";
    private static final String GATING_TYPE = "monitor";
    private static final String GATING_ID = "monitor-1";
    private static final String GATING_INDEX = ".alerting-config";

    /**
     * A request whose access is governed by another resource: the evaluator asks the plugin's resolver for that resource
     * and authorizes it, of the gating type, rather than the one the request names. The audit trail records the resolved
     * resource, since that is the one whose sharing record decided the request.
     */
    @Test
    public void testEvaluateAsync_gatedRequest_authorizesAndAuditsTheResolvedResource() {
        stubAuthenticatedUser();
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(List.of(GATING_ID), null));
        when(resourcePluginInfo.indexByType(GATING_TYPE)).thenReturn(GATING_INDEX);

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(true);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(List.of(GATING_ID)), eq(GATING_TYPE), eq("read"), any());

        ResourceAccessEvaluator.Evaluation evaluation = assertGatedEvaluation(true);

        assertThat(evaluation.resource().type(), equalTo(GATING_TYPE));
        assertThat(evaluation.resource().ids(), equalTo(List.of(GATING_ID)));
        assertThat(evaluation.resource().index(), equalTo(GATING_INDEX));
    }

    @Test
    public void testEvaluateAsync_gatedRequest_deniedWhenTheResolvedResourceDoesNotGrantTheAction() {
        stubAuthenticatedUser();
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(List.of(GATING_ID), null));
        when(resourcePluginInfo.indexByType(GATING_TYPE)).thenReturn(GATING_INDEX);

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(false);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(List.of(GATING_ID)), eq(GATING_TYPE), eq("read"), any());

        assertGatedEvaluation(false);
    }

    /**
     * Every resolved id must grant the action, which is what lets a request naming several resources be gated as a whole.
     */
    @Test
    public void testEvaluateAsync_gatedRequest_authorizesEveryResolvedId() {
        stubAuthenticatedUser();
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(List.of("monitor-1", "monitor-2"), null));
        when(resourcePluginInfo.indexByType(GATING_TYPE)).thenReturn(GATING_INDEX);

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(false);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(List.of("monitor-1", "monitor-2")), eq(GATING_TYPE), eq("read"), any());

        assertGatedEvaluation(false);
    }

    /**
     * Nothing resolved means no gating resource to name, so the request's own reference is audited and the denial still
     * leaves a trail.
     */
    @Test
    public void testEvaluateAsync_gatedRequest_auditsTheRequestWhenNothingResolves() {
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(List.of(), null));

        ResourceAccessEvaluator.Evaluation evaluation = assertGatedEvaluation(false);

        assertThat(evaluation.resource().type(), equalTo(REQUEST_TYPE));
        assertThat(evaluation.resource().ids(), equalTo(List.of()));
        verify(resourceAccessHandler, never()).hasPermission(anyCollection(), anyString(), anyString(), any());
    }

    @Test
    public void testEvaluateAsync_gatedRequest_deniedWhenResolutionFails() {
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(null, new RuntimeException("boom")));

        assertGatedEvaluation(false);
        verify(resourceAccessHandler, never()).hasPermission(anyCollection(), anyString(), anyString(), any());
    }

    /**
     * A gated request reporting no id must still be evaluated. The id check used to run first, which took exactly the case
     * the hook exists for, a create, out of resource evaluation entirely. {@code getResourceIndicesForProtectedTypes} is
     * deliberately not stubbed: a gated request's own index is not a resource index, so it must not be consulted.
     */
    @Test
    public void testShouldEvaluate_gatedRequestReportingNoId() {
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(true);
        when(protectedResourceTypesSetting.getDynamicSettingValue()).thenReturn(List.of(GATING_TYPE));
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(List.of(GATING_ID), null));

        GatedRequest request = new GatedRequest();
        assertThat(request.id(), equalTo(null));
        assertThat(evaluator.shouldEvaluate(request), equalTo(true));
    }

    @Test
    public void testShouldEvaluate_gatedRequestWhenGatingTypeIsNotProtected() {
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(true);
        when(protectedResourceTypesSetting.getDynamicSettingValue()).thenReturn(List.of("some-other-type"));
        when(resourcePluginInfo.gatingResolver(REQUEST_TYPE)).thenReturn(resolverReturning(List.of(GATING_ID), null));

        assertThat(evaluator.shouldEvaluate(new GatedRequest()), equalTo(false));
    }

    private ResourceAccessEvaluator.Evaluation assertGatedEvaluation(boolean expectedAllowed) {
        ActionListener<ResourceAccessEvaluator.Evaluation> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(new GatedRequest()), "read", callback);

        ArgumentCaptor<ResourceAccessEvaluator.Evaluation> captor = ArgumentCaptor.forClass(ResourceAccessEvaluator.Evaluation.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().response().isAllowed(), equalTo(expectedAllowed));
        return captor.getValue();
    }

    private GatingResourceResolver resolverReturning(Collection<String> gatingIds, Exception failure) {
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
            public void resolveGatingResourceIds(ActionRequest request, ActionListener<Collection<String>> listener) {
                if (failure != null) {
                    listener.onFailure(failure);
                } else {
                    listener.onResponse(gatingIds);
                }
            }
        };
    }

    /**
     * A request whose access is governed by a resource of another type, naming no resource of its own, which is the shape a
     * create has.
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
            return null;
        }
    }
}
