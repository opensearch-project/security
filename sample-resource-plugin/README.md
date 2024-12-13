# Resource Sharing and Access Control Plugin

This plugin demonstrates resource sharing and access control functionality, providing APIs to create, manage, and verify access to resources. The plugin enables fine-grained permissions for sharing and accessing resources, making it suitable for systems requiring robust security and collaboration.

## Features

- Create and delete resources.
- Share resources with specific users, roles and/or backend_roles with specific scope(s).
- Revoke access to shared resources for a list of or all scopes.
- Verify access permissions for a given user within a given scope.
- List all resources accessible to current user.

## API Endpoints

The plugin exposes the following six API endpoints:

### 1. Create Resource
- **Endpoint:** `POST /_plugins/sample_resource_sharing/create`
- **Description:** Creates a new resource. Also creates a resource sharing entry if security plugin is enabled.
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

### 2. Delete Resource
- **Endpoint:** `DELETE /_plugins/sample_resource_sharing/{resource_id}`
- **Description:** Deletes a specified resource owned by the requesting user.
- **Response:**
  ```json
  {
    "message": "Resource <resource_id> deleted successfully."
  }
  ```

### 3. Share Resource
- **Endpoint:** `POST /_plugins/sample_resource_sharing/share`
- **Description:** Shares a resource with specified users or roles with defined scope.
- **Request Body:**
  ```json
    {
      "resource_id" :  "{{ADMIN_RESOURCE_ID}}",
      "share_with" : {
        "SAMPLE_FULL_ACCESS": {
            "users": ["test"],
            "roles": ["test_role"],
            "backend_roles": ["test_backend_role"]
        },
        "READ_ONLY": {
            "users": ["test"],
            "roles": ["test_role"],
            "backend_roles": ["test_backend_role"]
        },
        "READ_WRITE": {
            "users": ["test"],
            "roles": ["test_role"],
            "backend_roles": ["test_backend_role"]
        }
      }
    }
  ```
- **Response:**
  ```json
    {
    "message": "Resource <resource-id> shared successfully."
    }
  ```

### 4. Revoke Access
- **Endpoint:** `POST /_plugins/sample_resource_sharing/revoke`
- **Description:** Revokes access to a resource for specified users or roles.
- **Request Body:**
  ```json
    {
      "resource_id" :  "<resource-id>",
      "entities" : {
            "users": ["test", "admin"],
            "roles": ["test_role", "all_access"],
            "backend_roles": ["test_backend_role", "admin"]
      },
      "scopes": ["SAMPLE_FULL_ACCESS", "READ_ONLY", "READ_WRITE"]
    }
  ```
- **Response:**
  ```json
    {
      "message": "Resource <resource-id> access revoked successfully."
    }
  ```

### 5. Verify Access
- **Endpoint:** `GET /_plugins/sample_resource_sharing/verify_resource_access`
- **Description:** Verifies if a user or role has access to a specific resource with a specific scope.
- **Request Body:**
    ```json
    {
      "resource_id": "<resource-id>",
      "scope": "SAMPLE_FULL_ACCESS"
    }
    ```
- **Response:**
  ```json
  {
    "message": "User has requested scope SAMPLE_FULL_ACCESS access to <resource-id>"
  }
  ```

### 6. List Accessible Resources
- **Endpoint:** `GET /_plugins/sample_resource_sharing/list`
- **Description:** Lists all resources accessible to the requesting user or role.
- **Response:**
  ```json
  {
    "resource-ids": [
        "<resource-id-1>",
        "<resource-id-2>"
    ]
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
   $ ./bin/opensearch-plugin install file: <path-to-this-plugin>/sample-resource-plugin/build/distributions/opensearch-sample-resource-plugin-3.0.0.0-SNAPSHOT.zip
   ```

## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors.
