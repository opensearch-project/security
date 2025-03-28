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
        final SystemIndexDescriptor systemIndexDescriptor =
            new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Sample index with resources");
        return Collections.singletonList(systemIndexDescriptor);
    }

    @Override
    public String getResourceType() {
        return SampleResource.class.getCanonicalName();
    }

    @Override
    public String getResourceIndex() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public ResourceParser<SampleResource> getResourceParser() {
        return new SampleResourceParser();
    }
}
```

---

## **Checklist for Implementing a Resource Plugin**

To properly integrate with the **Resource Sharing and Access Control SPI**, follow these steps:

### **1. Add Required Dependencies**
Include **`opensearch-security-client`** and **`opensearch-resource-sharing-spi`** in your **`build.gradle`** file.
Example:
```gradle
dependencies {
    implementation 'org.opensearch:opensearch-security-client:VERSION'
    implementation 'org.opensearch:opensearch-resource-sharing-spi:VERSION'
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
public class SampleResource implements Resource {
    private String id;
    private String owner;

    // Constructor, getters, setters, etc.

    @Override
    public String getResourceId() {
        return id;
    }
}
```

---

### **4. Implement a Resource Parser**
A **`ResourceParser`** is required to convert **resource data** from OpenSearch indices.
Example:
```java
public class SampleResourceParser implements ResourceParser<SampleResource> {
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

## **License**
This project is licensed under the **Apache 2.0 License**.

---

## **Copyright**
© OpenSearch Contributors.

---
