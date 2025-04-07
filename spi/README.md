# **Resource Sharing and Access Control SPI**

This **Service Provider Interface (SPI)** provides the necessary **interfaces and mechanisms** to implement **Resource Sharing and Access Control** in OpenSearch.

---

## **Usage**

A plugin that **defines a resource** and aims to implement **access control** over that resource must **extend** the `ResourceSharingExtension` class to register itself as a **Resource Plugin**.

### **Example: Implementing a Resource Plugin**
```java
public class SampleResourcePlugin extends Plugin implements SystemIndexPlugin, ResourceSharingExtension {

    // Override required methods

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
      final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Sample index with resources");
      return Collections.singletonList(systemIndexDescriptor);
    }

    @Override
    public Set<ResourceProvider> getResourceProviders() {
      return Set.of(
              new ResourceProvider(
                      SampleResource.class.getCanonicalName(), // class-name of the resource
                      RESOURCE_INDEX_NAME,                     // the index that stores resource, **must only store the type of resource defined in the line above**
                      new SampleResourceParser()               // parser to parse the resource
              )
      );
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
      ResourceSharingClientAccessor.setResourceSharingClient(resourceSharingClient);
    }
}
```

---

## **Checklist for Implementing a Resource Plugin**

To properly integrate with the **Resource Sharing and Access Control SPI**, follow these steps:

### **1. Add Required Dependencies**
Include **`opensearch-resource-sharing-spi`** in your **`build.gradle`** file.
Example:
```gradle
dependencies {
    compileOnly group: 'org.opensearch', name:'opensearch-resource-sharing-spi', version:"${opensearch_build_version}"
}
```

---

### **2. Register the Plugin Using the Java SPI Mechanism**
- Navigate to your plugin's `src/main/resources` folder.
- Locate or create the `META-INF/services` directory.
- Inside `META-INF/services`, create a file named:
  ```
  org.opensearch.security.spi.resources.ResourceSharingExtension
  ```
- Edit the file and add a **single line** containing the **fully qualified class name** of your plugin implementation.
  Example:
  ```
  org.opensearch.sample.SampleResourcePlugin
  ```
  > This step ensures that OpenSearch **dynamically loads your plugin** as a resource-sharing extension.

---

### **3. Declare a Resource Class**
Each plugin must define a **resource class** that implements the `Resource` interface.
Example:
```java
public class SampleResource implements ShareableResource {
    private String id;
    private String owner;

    // Constructor, getters, setters, etc.

    @Override
    public String getName() {
      return name;
    }
}
```

---

### **4. Implement a Resource Parser**
A **`ResourceParser`** is required to convert **resource data** from OpenSearch indices.
Example:
```java
public class SampleResourceParser implements ShareableResourceParser<SampleResource> {
    @Override
    public SampleResource parseXContent(XContentParser parser) throws IOException {
      return SampleResource.fromXContent(parser);
    }
}
```

---

### **5. Implement the `ResourceSharingExtension` Interface**
Ensure that your **plugin declaration class** implements `ResourceSharingExtension` and provides **all required methods**.

**Important:** Mark the resource **index as a system index** to enforce security protections.

---

### **6. Creating a Client Accessor **
To ensure a single instance of the `ResourceSharingClient`. CLIENT will be set by security plugin if enabled via `assignResourceSharingClient`. Default to `NoopResourceSharingClient` when CLIENT is null:

```java
/**
 * Accessor for resource sharing client supplied by the SPI.
 */
public class ResourceSharingClientAccessor {
  private static ResourceSharingClient CLIENT;

  private ResourceSharingClientAccessor() {}

  /**
   * Set the resource sharing client
   */
  public static void setResourceSharingClient(ResourceSharingClient client) {
    CLIENT = client;
  }

  /**
   * Get the resource sharing client
   */
  public static ResourceSharingClient getResourceSharingClient() {
    return CLIENT == null ? new NoopResourceSharingClient() : CLIENT;
  }
}
```

---

### **7. Using the Client in a Transport Action**
The following example demonstrates how to use the **Resource Sharing Client** inside a `TransportAction` to verify **delete permissions** before deleting a resource.

```java
@Inject
public DeleteResourceTransportAction(TransportService transportService, ActionFilters actionFilters, NodeClient nodeClient) {
  super(DeleteResourceAction.NAME, transportService, actionFilters, DeleteResourceRequest::new);
  this.transportService = transportService;
  this.nodeClient = nodeClient;
}

@Override
protected void doExecute(Task task, DeleteResourceRequest request, ActionListener<DeleteResourceResponse> listener) {
  String resourceId = request.getResourceId();
  if (resourceId == null || resourceId.isEmpty()) {
    listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
    return;
  }

  // Check permission to resource
  ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient();
  resourceSharingClient.verifyResourceAccess(resourceId, RESOURCE_INDEX_NAME, ActionListener.wrap(isAuthorized -> {
    if (!isAuthorized) {
      listener.onFailure(
              new OpenSearchStatusException("Current user is not authorized to delete resource: " + resourceId, RestStatus.FORBIDDEN)
      );
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
  }));
}

private void deleteResource(String resourceId, ActionListener<DeleteResponse> listener) {
  DeleteRequest deleteRequest = new DeleteRequest(RESOURCE_INDEX_NAME, resourceId).setRefreshPolicy(
          WriteRequest.RefreshPolicy.IMMEDIATE
  );

  nodeClient.delete(deleteRequest, listener);
}
```

---

## **Available Java APIs**

The **`ResourceSharingClient`** provides **four Java APIs** for **resource access control**, enabling plugins to **verify, share, revoke, and list** shareableResources.

**Package Location:**
[`org.opensearch.security.spi.resources.client.ResourceSharingClient`](../spi/src/main/java/org/opensearch/security/spi/resources/client/ResourceSharingClient.java)

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
    request.getResourceId(),
    RESOURCE_INDEX_NAME,
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

#### **Sample Request Flow:**

```mermaid
sequenceDiagram
    participant User as User
    participant Plugin as Plugin (Resource Plugin)
    participant SPI as Security SPI (opensearch-resource-sharing-spi)
    participant Security as Security Plugin (Resource Sharing)

    %% Step 1: Plugin registers itself as a Resource Plugin
    Plugin ->> Security: Registers as Resource Plugin via SPI (`ResourceSharingExtension`)
    Security -->> Plugin: Confirmation of registration

    %% Step 2: User interacts with Plugin API
    User ->> Plugin: Request to verify/share/revoke access to a resource

    %% Alternative flow based on Security Plugin status
    alt Security Plugin Disabled
    %% For verify: access is always granted
      Plugin ->> SPI: verifyResourceAccess (noop)
      SPI -->> Plugin: Response: Access Granted

    %% For share, revoke, and list: return 501 Not Implemented
      Plugin ->> SPI: shareResource (noop)
      SPI -->> Plugin: Error 501 Not Implemented

      Plugin ->> SPI: revokeResourceAccess (noop)
      SPI -->> Plugin: Error 501 Not Implemented

      Plugin ->> SPI: listAccessibleResources (noop)
      SPI -->> Plugin: Error 501 Not Implemented
    else Security Plugin Enabled
    %% Step 3: Plugin calls Java APIs declared by ResourceSharingClient
      Plugin ->> SPI: Calls Java API (`verifyResourceAccess`, `shareResource`, `revokeResourceAccess`, `listAccessibleResources`)

    %% Step 4: Request is sent to Security Plugin
      SPI ->> Security: Sends request to Security Plugin for processing

    %% Step 5: Security Plugin handles request and returns response
      Security -->> SPI: Response (Access Granted or Denied / Resource Shared or Revoked / List Resources )

    %% Step 6: Security SPI sends response back to Plugin
      SPI -->> Plugin: Passes processed response back to Plugin
    end

    %% Step 7: Plugin processes response and sends final response to User
    Plugin -->> User: Final response (Success / Error)
```

---

## **License**
This project is licensed under the **Apache 2.0 License**.

---

## **Copyright**
© OpenSearch Contributors.

---
