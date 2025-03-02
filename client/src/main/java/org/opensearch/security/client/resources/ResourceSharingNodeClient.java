package org.opensearch.security.client.resources;// package org.opensearch.security.spi.resources.client;
//
// import org.opensearch.core.action.ActionListener;
// import org.opensearch.transport.client.node.NodeClient;
//
// import java.util.List;
//
// public class ResourceSharingNodeClient {
//
// private final NodeClient nodeClient;
//
// public ResourceSharingClient(NodeClient nodeClient) {
// this.nodeClient = nodeClient;
// }
//
// public void verifyResourceAccess(String resourceId, String resourceIndex, String scope, ActionListener<Boolean> listener) {
// ResourceAccessRequest request = new ResourceAccessRequest(ResourceAccessRequest.OperationType.VERIFY, resourceId, resourceIndex, scope);
// execute(ResourceAccessAction.INSTANCE, request, wrapBooleanResponse(listener));
// }
//
// public void grantResourceAccess(String resourceId, String resourceIndex, String userOrRole, String accessLevel, ActionListener<Boolean>
// listener) {
// ResourceAccessRequest request = new ResourceAccessRequest(ResourceAccessRequest.OperationType.GRANT, resourceId, resourceIndex,
// userOrRole, accessLevel);
// execute(ResourceAccessAction.INSTANCE, request, wrapBooleanResponse(listener));
// }
//
// public void revokeResourceAccess(String resourceId, String resourceIndex, String userOrRole, ActionListener<Boolean> listener) {
// ResourceAccessRequest request = new ResourceAccessRequest(ResourceAccessRequest.OperationType.REVOKE, resourceId, resourceIndex,
// userOrRole);
// execute(ResourceAccessAction.INSTANCE, request, wrapBooleanResponse(listener));
// }
//
// public void listAccessibleResources(String userOrRole, ActionListener<List<String>> listener) {
// ResourceAccessRequest request = new ResourceAccessRequest(ResourceAccessRequest.OperationType.LIST, userOrRole);
// execute(ResourceAccessAction.INSTANCE, request, wrapListResponse(listener));
// }
//
// private ActionListener<ResourceAccessResponse> wrapBooleanResponse(ActionListener<Boolean> listener) {
// return ActionListener.wrap(
// response -> listener.onResponse(response.getHasPermission()),
// listener::onFailure
// );
// }
//
// private ActionListener<ResourceAccessResponse> wrapListResponse(ActionListener<List<String>> listener) {
// return ActionListener.wrap(
// response -> listener.onResponse(response.getAccessibleResources()),
// listener::onFailure
// );
// }
// }
