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
2. Under `src/main/resources` folder of the plugin, locate or create a folder `META-INF/services`and in the services folder, declare a file named `org.opensearch.security.spi.resources.ResourceSharingExtension`. Edit that file to add single line containing classpath of your plugin, e.g `org.opensearch.sample.SampleResourcePlugin`. This is required to utilize Java's Service Provider Interface mechanism.
3. Declare a resource class and implement `Resource` class from SPI.
4. Implement a `ResourceParser`.
5. Implement `ResourceSharingExtension` interface in the plugin declaration class, and implement required methods (as shown above). Ensure that resource index is marked as a system index.
6. Create a client accessor that will instantiate `ResourceSharingNodeClient`.
7. Use the methods provided by `ResourceSharingNodeClient` to implement resource access-control.


## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors.
