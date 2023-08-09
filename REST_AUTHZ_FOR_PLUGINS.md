# Authorization at REST Layer for plugins

This feature is introduced as an added layer of security on top of existing TransportLayer authorization framework. In order to leverage these feature some core changes need to be made at Route registration level. This document talks about how you can achieve this.

**NOTE:** This doesn't replace Transport Layer Authorization. Plugin developers may choose to skip creating transport actions for APIs that do not need interaction with the Transport Layer.

## Pre-requisites

The security plugin must be installed and operational in your OpenSearch cluster for this feature to work.

### How does NamedRoute authorization work?

Once the routes are defined as NamedRoute, they, along-with their handlers, will be registered the same way as Route objects. When a request comes in, `SecurityRestFilter.java` applies an authorization check which extracts information about the NamedRoute.
Next we get the unique name and actionNames associated with that route and evaluate these against existing `cluster_permissions` across all roles of the requesting user. If the authorization check succeeds, the request chain proceeds as normal. If it fails, a 401 response is returned to the user.

NOTE:
1. The action names defined in roles must exactly match the names of registered routes, or else, the request would be deemed unauthorized.
2. This check will not be implemented for plugins who do not use NamedRoutes.



### How to translate an existing Route to be a NamedRoute?

Here is a sample of an existing route converted to a named route:
Before:
```
public List<Route> routes() {
    return ImmutableList.of(
            new Route(GET, "/uri")
        );
}
```
With new scheme:
```
public List<NamedRoute> routes() {
    return ImmutableList.of(
            new NamedRoute.Builder().method(GET).path("/uri").uniqueName("plugin:uri").actionNames(Set.of("cluster:admin/opensearch/plugin/uri")).build()
        );
}
```

`actionNames()` are optional. They correspond to any current actions defined as permissions in roles.
Ensure that these name-to-route mappings are easily accessible to the cluster admins to allow granting access to these APIs.

### How does authorization in the REST Layer work?

We will continue on the above example of translating `/uri` from Route to NamedRoute.

Consider these roles are defined in the cluster:
```yaml
plugin_role:
  reserved: true
  cluster_permissions:
    - 'plugin:uri'

plugin_role_legacy:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/plugin/uri'
```

Successful authz scenarios for a user:
1. The user is mapped either to `plugin_role` OR `plugin_role_legacy`.
2. The user is mapped to both of these roles.
3. The user is mapped to `plugin_role` even if no `actionNames()` were registered for this route.

Unsuccessful authz scenarios for a user:
1. The user is not mapped any roles.
2. The user is mapped to a different role which doesn't grant the cluster permissions: `plugin:uri` OR `cluster:admin/opensearch/plugin/uri`/
3. The user is mapped to a role `plugin_role_other` which has a typo in action name, i.e.`plugin:uuri`.


### Sample API in Security Plugin

As part of this effort a new uri `GET /whoamiprotected` was introduced as a NamedRoute version of `GET /whoami`. Here is how you can test it:

#### roles.yml
```yaml
who_am_i_role:
  reserved: true
  cluster_permissions:
    - 'security:whoamiprotected'

who_am_i_role_legacy:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro_security/whoamiprotected'

who_am_i_role_no_perm:
  reserved: true
  cluster_permissions:
    - 'some_invalid_perm'

```

#### internal_users.yml
```yaml
who_am_i-user:
  hash: "$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG" #admin
  reserved: true
  description: "Demo user for ext-test"

who_am_i_legacy-user:
  hash: "$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG"
  reserved: true
  description: "Demo user for ext-test"

who_am_i_no_perm-user:
  hash: "$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG"
  reserved: true
  description: "Demo user for ext-test"
```

#### roles_mapping.yml
```yaml
who_am_i_role:
  reserved: true
  users:
    - "who_am_i-user"

who_am_i_role_legacy:
  reserved: true
  users:
    - "who_am_i_legacy-user"

who_am_i_role_no_perm:
  reserved: true
  users:
    - "who_am_i_no_perm-user"
```

Follow [DEVELOPER_GUIDE](DEVELOPER_GUIDE.md) to setup OpenSearch cluster and initialize security plugin. Once you have verified that security plugin is installed correctly and OpenSearch is running, execute following curl requests:
1. `curl -XGET https://who_am_i-user:admin@localhost:9200/_plugins/_security/whoami --insecure` should succeed.
2. `curl -XGET https://who_am_i_legacy-user:admin@localhost:9200/_plugins/_security/whoami --insecure` should succeed.
3. `curl -XGET https://who_am_i_no-perm-user:admin@localhost:9200/_plugins/_security/whoami --insecure` should fail.
4. `curl -XPOST ` to `/whoami` with all 3 users should succeed. This is because POST route is not a NamedRoute and hence no authorization check was made.
