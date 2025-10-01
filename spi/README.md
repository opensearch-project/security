
# Security SPI

This **Service Provider Interface (SPI)** provides the necessary **interfaces and mechanisms** to make security plugin extensible in OpenSearch.

### **Resource Sharing and Access Control Extension**

This extension point provides extending plugins with interfaces necessary to implement **Resource Sharing and Access Control** in OpenSearch.

---

### **Usage**

A plugin that **defines a resource** and aims to implement **access control** over that resource must **extend** the `ResourceSharingExtension` class to register itself as a **Resource Plugin**.

---

### **Checklist for plugins aiming to implement Resource Access Control**

To properly integrate with the **Resource Sharing and Access Control Extension**, follow these steps:

#### **1. Add Required Dependencies**
Include **`opensearch-security-spi`** in your **`build.gradle`** file.
Example:
```gradle
dependencies {
    compileOnly group: 'org.opensearch', name:'opensearch-security-spi', version:"${opensearch_build_version}"
}
```
---

#### **2. Declare a Resource Class**
Each plugin must define a **resource class** .
Example:
```java
public class SampleResource implements NamedWriteable, ToXContentObject{
    private String id;
    private String owner;

    // Constructor, getters, setters, etc.
}
```

---

#### **3. Declare Resource Index as System index**
**Important:** Mark the resource **index as a system index** to enforce security protections.

Example:
```java
public class SampleResourcePlugin extends Plugin implements SystemIndexPlugin {

    // Override required methods

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Sample index with resources");
        return Collections.singletonList(systemIndexDescriptor);
    }
}
```

---

#### **4. Implement the `ResourceSharingExtension` Interface**
Ensure that your **plugin declaration class** implements `ResourceSharingExtension` and provides **all required methods**.

```java
// Create a new extension point to register itself of a resource access control plugin
public class SampleResourceExtension implements ResourceSharingExtension {

  @Override
  public Set<ResourceProvider> getResourceProviders() {
    return Set.of(new ResourceProvider(SampleResource.class.getCanonicalName(), RESOURCE_INDEX_NAME));
  }

  @Override
  public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
    ResourceSharingClientAccessor.getInstance().setResourceSharingClient(resourceSharingClient);
  }
}
```

---

#### **5. Implement the `ResourceSharingClientAccessor` class**
Implement the ResourceSharingClientAccessor wrapper class To access the **ResourceSharingClient** instance. This class sets client to null when security is not present, else returns the client assigned by security plugin.

```java
public class ResourceSharingClientAccessor {
  private ResourceSharingClient CLIENT;

  private static ResourceSharingClientAccessor resourceSharingClientAccessor;

  private ResourceSharingClientAccessor() {}

  public static ResourceSharingClientAccessor getInstance() {
    if (resourceSharingClientAccessor == null) {
      resourceSharingClientAccessor = new ResourceSharingClientAccessor();
    }

    return resourceSharingClientAccessor;
  }

  /**
   * Set the resource sharing client
   */
  public void setResourceSharingClient(ResourceSharingClient client) {
    resourceSharingClientAccessor.CLIENT = client;
  }

  /**
   * Get the resource sharing client
   */
  public ResourceSharingClient getResourceSharingClient() {
    return resourceSharingClientAccessor.CLIENT;
  }
}
```

---

#### **6. Register the Plugin Using the Java SPI Mechanism**
- Navigate to your plugin's `src/main/resources` folder.
- Locate or create the `META-INF/services` directory.
- Inside `META-INF/services`, create a file named:
  ```
  org.opensearch.security.spi.resources.ResourceSharingExtension
  ```
- Edit the file and add a **single line** containing the **fully qualified class name** of your resource sharing extension implementation class.
  Example:
  ```
  org.opensearch.sample.SampleResourceExtension
  ```
  > This step ensures that OpenSearch **dynamically loads your plugin** as a resource-sharing extension.

---
#### **7. Implement DocRequest interface**

All ActionRequests related to resource must implement DocRequest interface. This is how the security plugin decides whether request is for a protected resource.

```java
public class ShareResourceRequest extends ActionRequest implements DocRequest {

    private final String resourceId;

    private final ShareWith shareWithRecipients;

    public ShareResourceRequest(String resourceId, ShareWith shareWithRecipients) {
        this.resourceId = resourceId;
        this.shareWithRecipients = shareWithRecipients;
    }

    public ShareResourceRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.shareWithRecipients = new ShareWith(in);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(this.resourceId);
        shareWithRecipients.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return this.resourceId;
    }

    public ShareWith getShareWith() {
        return shareWithRecipients;
    }

    @Override
    public String type() {
        return RESOURCE_TYPE;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return resourceId;
    }
}
```

---

#### **8. Using the Client in a Transport Action**
The following example demonstrates how to use the **Resource Sharing Client** inside a `TransportAction` to verify **delete permissions** before deleting a resource.

```java
public class ShareResourceTransportAction extends HandledTransportAction<ShareResourceRequest, ShareResourceResponse> {
  private static final Logger log = LogManager.getLogger(ShareResourceTransportAction.class);
  private final ResourceSharingClient resourceSharingClient;

  @Inject
  public ShareResourceTransportAction(TransportService transportService, ActionFilters actionFilters) {
    super(ShareResourceAction.NAME, transportService, actionFilters, ShareResourceRequest::new);
    this.resourceSharingClient = ResourceSharingClientAccessor.getInstance().getResourceSharingClient();
  }

  @Override
  protected void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
    if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
      listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
      return;
    }

    if (resourceSharingClient == null) {
      listener.onFailure(
              new OpenSearchStatusException(
                      "Resource sharing is not enabled. Cannot share resource " + request.getResourceId(),
                      RestStatus.NOT_IMPLEMENTED
              )
      );
      return;
    }
    ShareWith shareWith = request.getShareWith();
    resourceSharingClient.share(request.getResourceId(), RESOURCE_INDEX_NAME, shareWith, ActionListener.wrap(sharing -> {
      ShareWith finalShareWith = sharing == null ? null : sharing.getShareWith();
      ShareResourceResponse response = new ShareResourceResponse(finalShareWith);
      log.debug("Shared resource: {}", response.toString());
      listener.onResponse(response);
    }, listener::onFailure));
  }

}
```

---

### **Available Java APIs**

The **`ResourceSharingClient`** provides **four Java APIs** for **resource access control**, enabling plugins to **verify, share, revoke, and list** shareableResources.

**Package Location:**
[`org.opensearch.security.spi.resources.client.ResourceSharingClient`](../spi/src/main/java/org/opensearch/security/spi/resources/client/ResourceSharingClient.java)

---

#### **API Usage Examples**
Below are examples demonstrating how to use each API effectively.

---
#### **1. `verifyAccess`**
**Check access** for specific users, roles, or backend roles **for specified action**.

NOTE: This API should only be selectively used in case where implementing DocRequest interface for action-requests is not possible. Check out sample-plugin action-request classes to understand more.

##### **Method Signature:**
```java
void verifyAccess(String resourceId, String resourceIndex, String action, ActionListener<Boolean> listener);
```

##### **Example Usage:**
```java

resourceSharingClient.verifyAccess(
    request.getResourceId(),
    RESOURCE_INDEX_NAME,
    "indices:data/read/search",
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
> **Use Case:** Used when an **owner/admin wants to share a resource** with specific users or groups.

---

#### **2. `share`**
**Grants access to a resource** for specific users, roles, or backend roles.

##### **Method Signature:**
```java
void shareResource(String resourceId, String resourceIndex, SharedWithActionGroup.ActionGroupRecipients recipients, ActionListener<ResourceSharing> listener);
```

##### **Example Usage:**
```java

resourceSharingClient.share(
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

#### **3. `revoke`**
**Removes access permissions** for specified users, roles, or backend roles.

##### **Method Signature:**
```java
void revoke(String resourceId, String resourceIndex, SharedWithActionGroup.ActionGroupRecipients entitiesToRevoke, ActionListener<ResourceSharing> listener);
```

##### **Example Usage:**
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

#### **4. `getAccessibleResourceIds`**
**Retrieves ids of all shareableResources the current user has access to.**

##### **Method Signature:**
```java
void getAccessibleResourceIds(String resourceIndex, ActionListener<Set<String>> listener);
```

##### **Example Usage:**
```java
resourceSharingClient.getAccessibleResourceIds(RESOURCE_INDEX_NAME, ActionListener.wrap(resourceIds -> {
  log.debug("Fetched accessible resources ids: {}", resourceIds);
  getResourcesFromIds(resourceIds, listener);
}, listener::onFailure));
```
> **Use Case:** Helps a user identify **which shareableResources they can interact with**.

##### **Sample Request Flow:**

```mermaid
sequenceDiagram
participant User as User
participant Plugin as Plugin (Resource Plugin)
participant SPI as Security SPI (opensearch-security-spi)
participant Security as Security Plugin (Resource Sharing)

    %% Step 1: Plugin registers itself as a Resource Plugin
    Plugin ->> Security: Registers via SPI (`ResourceSharingExtension`)
    Security -->> Plugin: Confirmation

    %% Step 2: User calls Plugin API
    User ->> Plugin: create / share / revoke / get / delete resource request

    alt Security Plugin Disabled
      Plugin ->> SPI: share(...)
      SPI -->> Plugin: Error 501 Not Implemented

      Plugin ->> SPI: revoke(...)
      SPI -->> Plugin: Error 501 Not Implemented

      Plugin ->> SPI: getAccessibleResourceIds(...)
      SPI -->> Plugin: Error 501 Not Implemented
    else Security Plugin Enabled
      %% Automatic access verification happens within Security Plugin before handling
      Plugin ->> SPI: share(resourceId, actionGroup, targetUser/role)
      SPI ->> Security: share request
      Security -->> SPI: share success/error
      SPI -->> Plugin: share response

      Plugin ->> SPI: revoke(resourceId, actionGroup, targetUser/role)
      SPI ->> Security: revoke request
      Security -->> SPI: revoke success/error
      SPI -->> Plugin: revoke response

      Plugin ->> SPI: getAccessibleResourceIds(requestingUser, actionGroup)
      SPI ->> Security: list request
      Security -->> SPI: list of resource IDs
      SPI -->> Plugin: list response
    end

    %% Step 3: Plugin returns result to User
    Plugin -->> User: Final response (success or error)
```

---

## **License**
This project is licensed under the **Apache 2.0 License**.

---

## **Copyright**
© OpenSearch Contributors.

---
