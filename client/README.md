# Resource Sharing Client

This Client package provides a ResourceSharing client to be utilized by resource plugins to implement access control by communicating with security plugin.

## Usage

1. Create a client accessor with singleton pattern:
```java
public class ResourceSharingClientAccessor {
    private static ResourceSharingNodeClient INSTANCE;

    private ResourceSharingClientAccessor() {}

    /**
     * Get resource sharing client
     *
     * @param nodeClient node client
     * @return resource sharing client
     */
    public static ResourceSharingNodeClient getResourceSharingClient(NodeClient nodeClient, Settings settings) {
        if (INSTANCE == null) {
            INSTANCE = new ResourceSharingNodeClient(nodeClient, settings);
        }
        return INSTANCE;
    }
}
```

2. In your transport action doExecute function call the client.
Here is an example implementation of client being utilized to verify delete permissions before deleting a resource.
```java
@Override
protected void doExecute(Task task, DeleteResourceRequest request, ActionListener<DeleteResourceResponse> listener) {

    String resourceId = request.getResourceId();
    ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(nodeClient, settings);
    resourceSharingClient.verifyResourceAccess(
        resourceId,
        RESOURCE_INDEX_NAME,
        SampleResourceScope.PUBLIC.value(),
        ActionListener.wrap(isAuthorized -> {
            if (!isAuthorized) {
                listener.onFailure(new ResourceSharingException("Current user is not authorized to delete resource: " + resourceId));
                return;
            }

            // Authorization successful, proceed with deletion
            ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
            try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
                deleteResource(resourceId, ActionListener.wrap(deleteResponse -> {
                    if (deleteResponse.getResult() == DocWriteResponse.Result.NOT_FOUND) {
                        listener.onFailure(new ResourceNotFoundException("Resource " + resourceId + " not found."));
                    } else {
                        listener.onResponse(new DeleteResourceResponse("Resource " + resourceId + " deleted successfully."));
                    }
                }, exception -> {
                    log.error("Failed to delete resource: " + resourceId, exception);
                    listener.onFailure(exception);
                }));
            }
        }, exception -> {
            log.error("Failed to verify resource access: " + resourceId, exception);
            listener.onFailure(exception);
        })
    );
}
```
You can checkout other java APIs offered by the client by visiting ResourceSharingClient.java

## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors.
