# Resource Sharing and Access Control Plugin

This plugin demonstrates resource sharing and access control functionality, providing sample resource APIs and marking it as a resource sharing plugin via resource-sharing-spi. The access control is implemented on Security plugin and will be performed under the hood.

## Features

- Create, update and delete resources.

## API Endpoints

The plugin exposes the following six API endpoints:

### 1. Create Resource
- **Endpoint:** `POST /_plugins/sample_resource_sharing/create`
- **Description:** Creates a new resource. Behind the scenes a resource sharing entry will be created if security plugin is installed and feature is enabled.
- **Request Body:**
  ```json
  {
    "name": "<resource_name>"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Resource <resource_name> created successfully."
  }
  ```
### 2. Update Resource
- **Endpoint:** `POST /_plugins/sample_resource_sharing/update/{resourceId}`
- **Description:** Updates a resource.
- **Request Body:**
  ```json
  {
    "name": "<updated_resource_name>"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Resource <updated_resource_name> updated successfully."
  }
  ```

### 3. Delete Resource
- **Endpoint:** `DELETE /_plugins/sample_resource_sharing/delete/{resource_id}`
- **Description:** Deletes a specified resource owned by the requesting user.
- **Response:**
  ```json
  {
    "message": "Resource <resource_id> deleted successfully."
  }
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone git@github.com:opensearch-project/security.git
   ```

2. Navigate to the project directory:
   ```bash
   cd sample-resource-plugin
   ```

3. Build and deploy the plugin:
   ```bash
   $ ./gradlew clean build -x test -x integrationTest -x spotbugsIntegrationTest
   $ ./bin/opensearch-plugin install file: <path-to-this-plugin>/sample-resource-plugin/build/distributions/opensearch-sample-resource-plugin-<version-qualifier>.zip
   ```

## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors.
