/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
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

        ActionListener<PrivilegesEvaluatorResponse> callback = mock(ActionListener.class);

        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

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

    @Test
    public void testEvaluateAsync_multiIdRequest_authorizesEveryId() {
        stubAuthenticatedUser();
        MultiIdRequest req = new MultiIdRequest(List.of("id-1", "id-2"));

        doAnswer(inv -> {
            ActionListener<Boolean> listener = inv.getArgument(3);
            listener.onResponse(true);
            return null;
        }).when(resourceAccessHandler).hasPermission(eq(List.of("id-1", "id-2")), eq(TYPE), eq("read"), any());

        ActionListener<PrivilegesEvaluatorResponse> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

        ArgumentCaptor<PrivilegesEvaluatorResponse> captor = ArgumentCaptor.forClass(PrivilegesEvaluatorResponse.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().isAllowed(), equalTo(true));
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

        ActionListener<PrivilegesEvaluatorResponse> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

        ArgumentCaptor<PrivilegesEvaluatorResponse> captor = ArgumentCaptor.forClass(PrivilegesEvaluatorResponse.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().isAllowed(), equalTo(false));
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

        ActionListener<PrivilegesEvaluatorResponse> callback = mock(ActionListener.class);
        evaluator.evaluateAsync(ResourceAccessEvaluator.resourceRequest(req), "read", callback);

        ArgumentCaptor<PrivilegesEvaluatorResponse> captor = ArgumentCaptor.forClass(PrivilegesEvaluatorResponse.class);
        verify(callback).onResponse(captor.capture());
        assertThat(captor.getValue().isAllowed(), equalTo(false));
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

}
