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
    "resource_id": "<resource_id>",
    "status": "created"
  }
  ```

### 2. Delete Resource
- **Endpoint:** `DELETE /api/resource/{resource_id}`
- **Description:** Deletes a specified resource owned by the requesting user.
- **Response:**
  ```json
  {
    "resource_id": "<resource_id>",
    "status": "deleted"
  }
  ```

### 3. Share Resource
- **Endpoint:** `POST /api/resource/{resource_id}/share`
- **Description:** Shares a resource with specified users or roles with defined permissions.
- **Request Body:**
  ```json
  {
    "share_with": [
      { "type": "user", "id": "user123", "permission": "read_write" },
      { "type": "role", "id": "admin", "permission": "read_only" }
    ]
  }
  ```
- **Response:**
  ```json
  {
    "resource_id": "<resource_id>",
    "status": "shared"
  }
  ```

### 4. Revoke Access
- **Endpoint:** `DELETE /api/resource/{resource_id}/revoke`
- **Description:** Revokes access to a resource for specified users or roles.
- **Request Body:**
  ```json
  {
    "revoke_from": [ "user123", "role:admin" ]
  }
  ```
- **Response:**
  ```json
  {
    "resource_id": "<resource_id>",
    "status": "access_revoked"
  }
  ```

### 5. Verify Access
- **Endpoint:** `GET /api/resource/{resource_id}/verify`
- **Description:** Verifies if a user or role has access to a specific resource.
- **Query Parameters:**
    - `user_id` (optional): ID of the user.
    - `role` (optional): Role to verify.
- **Response:**
  ```json
  {
    "resource_id": "<resource_id>",
    "access": true,
    "permissions": "read_only"
  }
  ```

### 6. List Accessible Resources
- **Endpoint:** `GET /api/resources/accessible`
- **Description:** Lists all resources accessible to the requesting user or role.
- **Response:**
  ```json
  [
    {
      "resource_id": "<resource_id>",
      "name": "<resource_name>",
      "permissions": "read_write"
    },
    {
      "resource_id": "<resource_id>",
      "name": "<resource_name>",
      "permissions": "read_only"
    }
  ]
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   ```

2. Navigate to the project directory:
   ```bash
   cd resource-access-plugin
   ```

3. Build and deploy the plugin:
   ```bash
   <build_command>
   ```

4. Configure the plugin in your environment.

## Configuration

- Ensure that the appropriate access control settings are enabled in your system.
- Define user roles and permissions to match your use case.

## License

This code is licensed under the Apache 2.0 License.

## Copyright

Copyright OpenSearch Contributors.
