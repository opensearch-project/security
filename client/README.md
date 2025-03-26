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
     * @return A singleton instance of ResourceSharingNodeClient.
     */
    public static ResourceSharingNodeClient getResourceSharingClient(NodeClient nodeClient, Settings settings) {
        if (INSTANCE == null) {
            INSTANCE = new ResourceSharingNodeClient(nodeClient, settings);
        }
        return INSTANCE;
    }
}
```

---

### **2. Using the Client in a Transport Action**
The following example demonstrates how to use the **Resource Sharing Client** inside a `TransportAction` to verify **delete permissions** before deleting a resource.

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
                listener.onFailure(new UnauthorizedResourceAccessException("Current user is not authorized to delete resource: " + resourceId));
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
void shareResource(String resourceId, String resourceIndex, Map<String, Object> shareWith, ActionListener<ResourceSharing> listener);
```

#### **Example Usage:**
```java
Map<String, Object> shareWith = Map.of(
    "users", List.of("user_1", "user_2"),
    "roles", List.of("admin_role"),
    "backend_roles", List.of("backend_group")
);

resourceSharingClient.shareResource(
    "resource-123",
    "resource_index",
    shareWith,
    ActionListener.wrap(response -> {
        System.out.println("Resource successfully shared with: " + shareWith);
    }, e -> {
        System.err.println("Failed to share resource: " + e.getMessage());
    })
);
```
> **Use Case:** Used when an **owner/admin wants to share a resource** with specific users or groups.

---

### **3. `revokeResourceAccess`**
**Removes access permissions** for specified users, roles, or backend roles.

#### **Method Signature:**
```java
void revokeResourceAccess(String resourceId, String resourceIndex, Map<String, Object> entitiesToRevoke, ActionListener<ResourceSharing> listener);
```

#### **Example Usage:**
```java
Map<String, Object> entitiesToRevoke = Map.of(
    "users", List.of("user_2"),
    "roles", List.of("viewer_role")
);

resourceSharingClient.revokeResourceAccess(
    "resource-123",
    "resource_index",
    entitiesToRevoke,
    ActionListener.wrap(response -> {
        System.out.println("Resource access successfully revoked for: " + entitiesToRevoke);
    }, e -> {
        System.err.println("Failed to revoke access: " + e.getMessage());
    })
);
```
> **Use Case:** When a user no longer needs access to a **resource**, their permissions can be revoked.

---

### **4. `listAllAccessibleResources`**
**Retrieves all shareableResources the current user has access to.**

#### **Method Signature:**
```java
void listAllAccessibleResources(String resourceIndex, ActionListener<Set<? extends Resource>> listener);
```

#### **Example Usage:**
```java
resourceSharingClient.listAllAccessibleResources(
    "resource_index",
    ActionListener.wrap(shareableResources -> {
        for (Resource resource : shareableResources) {
            System.out.println("Accessible Resource: " + resource.getId());
        }
    }, e -> {
        System.err.println("Failed to list accessible shareableResources: " + e.getMessage());
    })
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
