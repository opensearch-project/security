# **Resource Sharing Client**

This package provides a **ResourceSharing client** that resource plugins can use to **implement access control** by communicating with the **OpenSearch Security Plugin**.

---

## **Usage**

### **1. Creating a Client Accessor with Singleton Pattern**
To ensure a single instance of the `ResourceSharingNodeClient`, use the **Singleton pattern**:

```java
public class ResourceSharingClientAccessor {
    private static ResourceSharingNodeClient INSTANCE;

    private ResourceSharingClientAccessor() {}

    /**
     * Get the resource sharing client instance.
     *
     * @param nodeClient The OpenSearch NodeClient instance.
     * @param settings   The OpenSearch settings.
     * @param version    The node version.s
     * @return A singleton instance of ResourceSharingNodeClient.
     */
    public static ResourceSharingNodeClient getResourceSharingClient(NodeClient nodeClient, Settings settings, Version version) {
        if (INSTANCE == null) {
            INSTANCE = new ResourceSharingNodeClient(nodeClient, settings, version);
        }
        return INSTANCE;
    }
}
```

---

### **2. Using the Client in a Transport Action**
The following example demonstrates how to use the **Resource Sharing Client** inside a `TransportAction` to verify **delete permissions** before deleting a resource.

```java
@Inject
public DeleteResourceTransportAction(
    Settings settings,
    TransportService transportService,
    ActionFilters actionFilters,
    NodeClient nodeClient
) {
    super(DeleteResourceAction.NAME, transportService, actionFilters, DeleteResourceRequest::new);
    this.transportService = transportService;
    this.nodeClient = nodeClient;
    this.settings = settings;
}

@Override
protected void doExecute(Task task, DeleteResourceRequest request, ActionListener<DeleteResourceResponse> listener) {
    String resourceId = request.getResourceId();

    Version nodeVersion = transportService.getLocalNode().getVersion();
    ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(nodeClient, settings, nodeVersion);

    resourceSharingClient.verifyResourceAccess(
        resourceId,
        RESOURCE_INDEX_NAME,
        ActionListener.wrap(isAuthorized -> {
            if (!isAuthorized) {
                listener.onFailure(new OpenSearchStatusException("Current user is not authorized to delete resource: " + resourceId, RestStatus.FORBIDDEN));
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

---

## **Available Java APIs**

The **`ResourceSharingClient`** provides **four Java APIs** for **resource access control**, enabling plugins to **verify, share, revoke, and list** shareableResources.

**Package Location:**
[`org.opensearch.security.client.resources.ResourceSharingClient`](../client/src/main/java/org/opensearch/security/client/resources/ResourceSharingClient.java)

---

### **API Usage Examples**
Below are examples demonstrating how to use each API effectively.

---

### **1. `verifyResourceAccess`**
**Checks if the current user has access to a resource**.

#### **Method Signature:**
```java
void verifyResourceAccess(String resourceId, String resourceIndex, ActionListener<Boolean> listener);
```

#### **Example Usage:**
```java
resourceSharingClient.verifyResourceAccess(
    "resource-123",
    "resource_index",
    ActionListener.wrap(isAuthorized -> {
        if (isAuthorized) {
            System.out.println("User has access to the resource.");
        } else {
            System.out.println("Access denied.");
        }
    }, e -> {
        System.err.println("Failed to verify access: " + e.getMessage());
    })
);
```
> **Use Case:** Before performing operations like **deletion or modifications**, ensure the user has the right permissions.

---

### **2. `shareResource`**
**Grants access to a resource** for specific users, roles, or backend roles.

#### **Method Signature:**
```java
void shareResource(String resourceId, String resourceIndex, SharedWithActionGroup.ActionGroupRecipients recipients, ActionListener<ResourceSharing> listener);
```

#### **Example Usage:**
```java

resourceSharingClient.shareResource(
    request.getResourceId(),
    RESOURCE_INDEX_NAME,
    request.getShareWith(),
    ActionListener.wrap(sharing -> {
        ShareResourceResponse response = new ShareResourceResponse(sharing.getShareWith());
        listener.onResponse(response);
    }, listener::onFailure)
);
```
> **Use Case:** Used when an **owner/admin wants to share a resource** with specific users or groups.

---

### **3. `revokeResourceAccess`**
**Removes access permissions** for specified users, roles, or backend roles.

#### **Method Signature:**
```java
void revokeResourceAccess(String resourceId, String resourceIndex, SharedWithActionGroup.ActionGroupRecipients entitiesToRevoke, ActionListener<ResourceSharing> listener);
```

#### **Example Usage:**
```java
resourceSharingClient.revokeResourceAccess(
    request.getResourceId(),
    RESOURCE_INDEX_NAME,
    request.getEntitiesToRevoke(),
    ActionListener.wrap(success -> {
        RevokeResourceAccessResponse response = new RevokeResourceAccessResponse(success.getShareWith());
            listener.onResponse(response);
        }, listener::onFailure)
);
```
> **Use Case:** When a user no longer needs access to a **resource**, their permissions can be revoked.

---

### **4. `listAllAccessibleResources`**
**Retrieves all shareableResources the current user has access to.**

#### **Method Signature:**
```java
void listAllAccessibleResources(String resourceIndex, ActionListener<Set<? extends ShareableResource>> listener);
```

#### **Example Usage:**
```java
resourceSharingClient.listAllAccessibleResources(
        RESOURCE_INDEX_NAME,
        ActionListener.wrap(
                resources -> {
                    listener.onResponse(new GetResourceResponse((Set<SampleResource>) resources));
                    },
                failure -> {
                    if (failure instanceof OpenSearchStatusException && ((OpenSearchStatusException) failure).status().equals(RestStatus.NOT_IMPLEMENTED)) {
                        getAllResourcesAction(listener);
                        return;
                    }
                    listener.onFailure(failure);
                }
        )
);
```
> **Use Case:** Helps a user identify **which shareableResources they can interact with**.

---

## **Conclusion**
These APIs provide essential methods for **fine-grained resource access control**, enabling:

✔ **Verification** of resource access.
✔ **Granting and revoking** access dynamically.
✔ **Retrieval** of all accessible shareableResources.

For further details, refer to the [`ResourceSharingClient` Java class](../client/src/main/java/org/opensearch/security/client/resources/ResourceSharingClient.java).

---

## **License**
This project is licensed under the **Apache 2.0 License**.

---

## **Copyright**
© OpenSearch Contributors.
