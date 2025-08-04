# OpenSearch Security Plugin - Resource Sharing and Access Control

## Overview

Starting from version **3.2.0**, the OpenSearch Security Plugin introduces a **resource sharing framework** that enables **document-level access control** across plugins. This feature allows a **resource owner** (creator of a document) and entities with sufficient access to share that resource with specific **users, roles, or backend_roles** at configurable **access levels** (e.g., `read_only`, `read_write`). Access-levels are nothing but action-groups.

> A "resource" is currently defined as a **document in an index**. This sharing model powers resource-level security in OpenSearch Dashboards and other REST clients.

**Key capabilities:**
- Share access to your resource with fine-grained control
- Manage sharing configurations using a REST API
- Migrate existing sharing data from plugin-managed storage into the centralized security-owned index

The implementation proposal and discussion can be found here:  
🔗 [GitHub Issue #4500](https://github.com/opensearch-project/security/issues/4500)

---

## 1. Migration API (for plugin developers / cluster admins)

The **Migration API** is a one-time utility for cluster admins to migrate legacy sharing metadata from plugin indices into the centralized **resource-sharing index** owned by the security plugin.

### `POST /_plugins/_security/api/resources/migrate`

### **Description:**
Read documents from a plugin’s index and migrate ownership and backend role-based access into the centralized sharing model.

**Request Body**

| Parameter              | Type    | Required | Description                                                                 |
|------------------------|---------|----|-----------------------------------------------------------------------------|
| `source_index`         | string  | yes | Name of the plugin index containing the existing resource documents        |
| `username_path`        | string  | yes | JSON Pointer to the username field inside each document (e.g., `/owner`)   |
| `backend_roles_path`   | string  | yes | JSON Pointer to the backend_roles field (must point to a JSON array)       |
| `default_access_level` | string  | no | Default access level to assign migrated backend_roles (default: `"default"`) |

**Example Request**
`POST /_plugins/_security/api/resources/migrate`
**Request Body:**
```json
{
  "source_index": "sample_plugin_index",
  "username_path": "/owner",
  "backend_roles_path": "/access/backend_roles",
  "default_access_level": "read_only"
}
```

**Response:**

```json
{
  "summary": "Migration complete. migrated 10; skippedNoUser 2; failed 1",
  "skippedResources": ["doc-17", "doc-22"]
}
```

---

## 2. Resource Sharing API

The **Resource Sharing API** allows users (typically via OpenSearch Dashboards or REST clients) to control **who can access their resources** and at what **access level**.

A **resource owner** (i.e., the document creator) can:
- Share access with specific users, roles, or backend roles
  - Users with sufficient permission can further share or revoke access to resource
- Grant read-only or read-write permissions
- Revoke or update access over time

### Base Path:
```
/_plugins/_security/api/resource/share
```

---

### 1. `PUT /_plugins/_security/api/resource/share`

**Description:**  
Creates or replaces sharing settings for a resource.

**Request Body:**

```json
{
  "resource_id": "resource-123",
  "resource_index": "my-resource-index",
  "share_with": {
    "read_only": {
      "users": ["alice"],
      "roles": ["readers"],
      "backend_roles": ["data-readers"]
    },
    "read_write": {
      "users": ["bob"]
    }
  }
}
```

**Response:**

```json
{
  "sharing_info": {
    "resource_id": "resource-123",
    "created_by": { "username": "admin" },
    "share_with": {
      "read_only": {
        "users": ["alice"],
        "roles": ["readers"],
        "backend_roles": ["data-readers"]
      },
      "read_write": {
        "users": ["bob"]
      }
    }
  }
}
```

---

### 2. `PATCH /_plugins/_security/api/resource/share`

**Description:**  
Updates sharing settings by **adding** or **removing** recipients at any access level. Unlike `PUT`, this is a **non-destructive** operation.

**Request Body:**

```json
{
  "resource_id": "resource-123",
  "resource_index": "my-resource-index",
  "patch": {
    "share_with": {
      "read_only": {
        "users": ["charlie"]
      }
    },
    "revoke": {
      "read_only": {
        "users": ["alice"]
      },
      "read_write": {
        "users": ["bob"]
      }
    }
  }
}
```

**Response:**

```json
{
  "sharing_info": {
    "resource_id": "resource-123",
    "created_by": { "username": "admin" },
    "share_with": {
      "read_only": {
        "users": ["charlie"],
        "roles": ["readers"],
        "backend_roles": ["data-readers"]
      },
      "read_write": {}
    }
  }
}
```

#### Allowed Keys in `patch`:
- `"share_with"` – Adds recipients
- `"revoke"` – Removes recipients

---

### 3. `GET /_plugins/_security/api/resource/share?resource_id=<id>&resource_index=<index>`

**Description:**  
Retrieves the current sharing configuration for a given resource.

**Example Request:**

```
GET /_plugins/_security/api/resource/share?resource_id=resource-123&resource_index=my-resource-index
```

**Response:**

```json
{
  "sharing_info": {
    "resource_id": "resource-123",
    "created_by": { "username": "admin" },
    "share_with": {
      "read_only": {
        "users": ["charlie"],
        "roles": ["readers"],
        "backend_roles": ["data-readers"]
      },
      "read_write": {}
    }
  }
}
```

---

## Who Can Use This?

| API                                            | Permission Required               | Intended User     |
|------------------------------------------------|-----------------------------------|-------------------|
| `POST /_plugins/_security/api/resources/migrate` | REST admin or Super admin         | Cluster admin     |
| `PUT /_plugins/_security/api/resource/share`     | Resource Owner                    | Dashboards / REST |
| `PATCH /_plugins/_security/api/resource/share`    | Resource Owner / share permission | Dashboards / REST |
| `GET /_plugins/_security/api/resource/share`      | Resource Owner / read permission  | Dashboards / REST |

---

## When to Use

| Use Case                                            | API                        |
|-----------------------------------------------------|----------------------------|
| Migrating existing plugin-specific sharing configs  | `POST /_plugins/_security/api/resources/migrate` |
| Sharing a document with another user or role        | `PUT /_plugins/_security/api/resource/share`   |
| Granting/revoking access without affecting others   | `PATCH /_plugins/_security/api/resource/share` |
| Fetching the current sharing status of a resource   | `GET /_plugins/_security/api/resource/share`   |
