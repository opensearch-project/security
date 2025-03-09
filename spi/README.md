# Resource Sharing and Access Control SPI

This SPI provides interfaces to implement Resource Sharing and Access Control.


## Usage

A plugin defining a resource and aiming to implement access control over that resource must extend ResourceSharingExtension class to register itself as a Resource Plugin. Here is an example:

```java

public class SampleResourcePlugin extends Plugin implements SystemIndexPlugin, ResourceSharingExtension {

    // override any required methods

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Sample index with resources");
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

Checklist for resource plugin:
1. Add a dependency on `opensearch-security-client` and `opensearch-resource-sharing-spi` in build.gradle.
2. Declare a resource class and implement `Resource` class from SPI.
3. Implement a `ResourceParser`.
4. Implement `ResourceSharingExtension` interface in the plugin declaration class, and implement required methods (as shown above). Ensure that resource index is marked as a system index.
5. Create a client accessor that will instantiate `ResourceSharingNodeClient`.
6. Use the methods provided by `ResourceSharingNodeClient` to implement resource access-control.


## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors.
