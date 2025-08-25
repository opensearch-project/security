# Resource Sharing and Access Control Plugin

This plugin demonstrates resource sharing and access control functionality, providing sample resource APIs and marking it as a resource sharing plugin via resource-sharing-spi. The access control is implemented on Security plugin and will be performed under the hood.
At present only admin and resource owners can modify/delete the resource

## PreRequisites

Publish SPI to local maven before proceeding:
```shell
./gradlew clean :opensearch-security-spi:publishToMavenLocal
```

System index feature must be enabled to prevent direct access to resource. Add the following setting in case it has not already been enabled.
```yml
plugins.security.system_indices.enabled: true
```

## Features

- Create, update, get, delete SampleResource, as well as share and revoke access to a resource.

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


## User setup:
1. **No Index-Level Permissions Required**
    - **Resource access is controlled at the cluster level**.
    - Users **do not** need explicit index-level permissions to access shared resources.

2. **Sample Role Configurations**
    - Below are **two sample roles** demonstrating how to configure permissions in `roles.yml`:

    ```yaml
    sample_full_access:
     cluster_permissions:
       - 'cluster:admin/sample-resource-plugin/*'

    sample_read_access:
     cluster_permissions:
       - 'cluster:admin/sample-resource-plugin/get'
    ```

4. **Interaction Rules**
    - If a **user is not the resource owner**, they must:
        - **Have the resource shared with them** via the resource-sharing API with appropriate action group.
    - A user **without** the necessary `sample-resource-plugin` cluster permissions:
        - **Cannot access the resource**, even if it is shared with them.
    - A user **with `sample-resource-plugin` permissions** but **without a shared resource**:
        - **Cannot access the resource**, since resource-level access control applies.
    - A user **with full-access to the resource** will be able to **update and delete that resource**.
        - Owners and super-admin get full-access by default.


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
    "message": "Created resource: 9UdrWpUB99GNznAOkx43"
  }
  ```

### 2. Update Resource
- **Endpoint:** `POST /_plugins/sample_resource_sharing/update/{resourceId}`
- **Description:** Updates a resource if current user has access to it.
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

### 4. Get Resource
- **Endpoint:** `GET /_plugins/sample_resource_sharing/get/{resource_id}`
- **Description:** Get a specified resource owned by or shared_with the requesting user, if the user has access to the resource, else fails.
- **Response:**
  ```json
  {
    "resources" : [{
      "name" : "<resource_name>",
      "description" : null,
      "attributes" : null
    }]
  }
  ```
- **Endpoint:** `GET /_plugins/sample_resource_sharing/get`
- **Description:** Get all resources owned by or shared with the requesting user.
- **Response:**
  ```json
  {
    "resources" : [{
      "name" : "<resource_name>",
      "description" : null,
      "attributes" : null
    }]
  }
  ```

### 5. Share Resource
- **Endpoint:** `POST /_plugins/sample_resource_sharing/share/{resource_id}`
- **Description:** Shares a resource with the intended entities.
- **Request Body:**
  ```json
  {
    "share_with": {
      "read_only": {
        "users": [ "sample_user" ]
      }
    }
  }
  ```
- **Response:**
  ```json
    {
      "share_with": {
        "read_only": {
          "users": [ "sample_user" ]
        }
      }
    }
  ```

### 6. Revoke Resource Access
- **Endpoint:** `POST /_plugins/sample_resource_sharing/revoke/{resource_id}`
- **Description:** Shares a resource with the intended entities.
- **Request Body:**
  ```json
    {
      "entities_to_revoke": {
        "read_only": {
          "users": [ "sample_user" ]
        }
      }
    }
  ```
- **Response:**
  ```json
    {
      "share_with" : {
        "read_only": {
          "users" : [ ]
        }
      }
    }
  ```

### 7. Search Resource
- **Endpoint:** `POST /_plugins/sample_resource_sharing/search`, `GET /_plugins/sample_resource_sharing/search`
- **Description:** Search for one ore more resources.
- **Request Body:**
  ```json
    {
      "query": {
        "match_all": {}
      }
    }
  ```
- **Response:**
  ```json
    {"_index":".sample_resource","_id":"x2him5gBNtGh_iGqK19z","_score":1.0,"_source":{"name":"sampleUpdateUser","description":null,"attributes":null,"user":null}}
  ```

## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors.
