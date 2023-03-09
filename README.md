# InfluxDB v2 Vault Database Plugin
This plugin allows to use Vault to manage InfluxDB version 2 authentication.

## Prerequisites
### InfluxDB
After initialization, you will need to create a dedicated user account for Vault, add it to an organization and issue an authorization (token) that carries all necessary permissions.

Creating a user account is easy:
```bash
influx user create --name vault --org $INFLUX_ORG
```

Creating an authorization is more involved since the `influx auth create` command scopes `authorizations` permissions to an organization, but this plugin needs them to apply to all organizations. Furthermore, the root token needs to carry all permissions you intend to issue to clients.

Creating the authorization:
```bash
curl -H "Authorization: Token ${INFLUX_TOKEN}" -d "$definitions" "https://${INFLUX_HOST}/api/v2/authorizations"
```

Example authorization definition:
```json
{
    "orgId": "1337cafebabe1337",
    "userID": "deadbeefdabbad00",
    "permissions": [
        {
            "action": "read",
            "resource": {
                "type": "authorizations"
            }
        },
        {
            "action": "write",
            "resource": {
                "type": "authorizations"
            }
        },
        {
            "action": "read",
            "resource": {
                "type": "orgs"
            }
        },
        {
            "action": "write",
            "resource": {
                "type": "orgs"
            }
        },
        {
            "action": "read",
            "resource": {
                "type": "users"
            }
        },
        {
            "action": "write",
            "resource": {
                "type": "users"
            }
        },
        {
            "action": "read",
            "resource": {
                "type": "buckets"
            }
        },
        {
            "action": "write",
            "resource": {
                "type": "buckets"
            }
        }
    ]
}
```

### Vault
First, ensure your Vault configuration defines `plugin_directory` and `api_address` correctly (the latter is used for inter-process communication, consider TLS certificates!).

Currently, there are no binary releases, hence you will need to compile this plugin, e.g.:

```bash
go build ./cmd/influxdb2-database-plugin
# or gox -osarch="linux/amd64" ./cmd/influxdb2-database-plugin
```

Then move the plugin into `plugin_directory`, ensure correct ownership/permissions and register it:

```bash
vault plugin register -sha256=${BINARY_SHA_SUM} influxdb2-database-plugin
```

## Configuration
### Connection
* `host`: FQDN/IP address of the InfluxDB v2 server. **Required.**
* `port`: The port the InfluxDB v2 server is listening on (int). Defaults to `8086`.
* `organization`: The organization the `vault` user is part of. Will also be default organization for roles. **Required.**
* `password`: The authorization token you created. **Required.**
* `tls`: Whether to enable TLS. Defaults to `false`.
* `insecure_tls`: Whether to skip verifying server certificates. Defaults to `false`.
* `ca_cert`: The path to a PEM-encoded CA cert file to use to verify the InfluxDB v2 server's identity.
* `ca_path`: The path to a directory of PEM-encoded CA cert files to use to verify the InfluxDB v2 server's identity.
* `client_cert`: The path to a certificate for the InfluxDB v2 client to present for communication.
* `client_key`: The path to the key for the InfluxDB v2 client to use for communication.
* `tls_min_version`: Minimum acceptable TLS version (string). Defaults to "1.2"
* `connect_timeout`: Timeout for HTTP connections. Defaults to `5s`.

### Role
A role's `creation_statements` define which permissions the issued authorization will carry and, optionally, the organization the user will belong to. It should be a list containing a single, JSON-encoded string value. The JSON data can contain the following fields:
* `read`: A list of resources to allow read access to.
* `write`: A list of resources to allow write access to.
* `read_bucket`: A list of bucket names to allow read access to.
* `write_bucket`: A list of bucket names to allow write access to.
* `org`: A valid organization name the user should belong to. Defaults to the connection's organization.

### Credentials
InfluxDB v2 is a bit weird with authentication and authorization. User accounts are used in some places, but the entity providing authentication and describing resource access (authorization) is called Authorization (~ API Key). It works like a Vault token. A user name therefore is separate from the duties Vault usually fulfills.

Generated user names match the Vault database role name by default to avoid unexpected behavior in InfluxDB. You can change that behavior by specifying an alternative username template. Mind that by default, this plugin revokes Authorizations only.

* `username_template`: A template describing username generation. See the Vault docs for details. Defaults to the database role name.
* `ephemeral_users`: When the template above generates unique usernames, enable deletion of user accounts during lease revocation. Defaults to `false`.
* `description_template`: A template describing the authorization. See the Vault docs for details. Defaults to the requesting token's display name + database role name.

## Notes
* This plugin is in very early development.
* Ironically, to support the new InfluxDB API, this plugin needs to be written using the old (v4) SDK for Vault database plugins, which is deprecated. The reason is that tokens must be generated on the InfluxDB server and cannot be forced by Vault. Until there is a workaround, this plugin might stop working with future Vault releases once support for the old SDK is removed entirely.

## References
* https://github.com/hashicorp/vault/pull/14035
* https://github.com/hashicorp/vault/issues/12492
