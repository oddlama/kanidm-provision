[About](#-kanidm-provisioning-tool) \| [Usage](#usage) \| [JSON Schema](#json-schema)

## 🦀 Kanidm Provisioning Tool

This is a tiny helper utility that uses kanidm's API to provision
users, groups and oauth2 systems. This tool is needed to allow declarative
provisioning of kanidm in NixOS, but can be used on any other system as well.
This tool is not affiliated with kanidm itself. Use at your own discretion.

Two optional patches are provided for kanidm that allow you to:
- provision oauth2 basic secrets
- use a specific password when recovering admin account credentials.

Currently this tool supports the following provisioning operations which should suffice for basic SSO and OIDC needs.
PRs are of course welcome!

| | Provisioning Feature
---|---
| |
| 👪 | **Groups**
| ✅ | Create/delete
| ✅ | Members
| ❌ | Unix attributes
| |
| 🧑 | **Persons**
| ✅ | Create/delete
| ✅ | Attributes (displayname, legalname, mail)
| ❌ | Credentials
| ❌ | SSH
| ❌ | Unix attributes
| ❌ | Radius
| |
| 🌐 | **Oauth2**
| ✅ | Create/delete (basic, public)
| ✅ | Attributes (origin url, origin landing, pkce enable, prefer short username)
| ✅* | Basic secret
| ✅ | Scope maps
| ✅ | Supplementary scope maps
| ✅ | Claim maps

(*): Requires patch, [see below](#provisioning-oauth2-basic-secrets).

## Usage

Build the utility simply by running:

```bash
> cargo build
```

Afterwards you can apply a state file to your kanidm instance by executing:

```bash
KANIDM_PROVISION_IDM_ADMIN_TOKEN="your-idm-admin-token" \
  kanidm-provision --url 'https://auth.example.com' --state state.json
```

## Orphan removal

This tool automatically adds all created entities to a tracking group so
whenever something is removed from the state file in the future, the change
can be reflected in kanidm automatically.

To prevent this kind of orphan removal, you can to pass `--no-auto-remove`.
Removing for example a group from the state file will then not cause any
changes in kanidm, unless the state file explicitly specifies `present: false`.

This automatic tracking does not work for oauth2 claim maps, since claim maps
are not a separate entity in kanidm. To work around that, each oauth2 resource server
has a `removeOrphanedClaimMaps` option that will delete any claim maps on the resource
server that haven't been created by this tool. `--no-auto-remove` has no effect on that option.

## Provisioning oauth2 basic secrets

This tool is able to provision basic secrets if you build kanidm
with the patch provided in [./patches](./patches). This adds a new endpoint
that allows modifying the basic secret of any oauth2 resource server via a new API endpoint,
instead of only allowing to read the value generated by kanidm.

Some applications may have issues with certain characters appearing in the basic secret, especially with `&` which
causes issues when the application does not properly urlencode the secret. While this is a bug
in the application, you can prevent this from happening by generating new secret values with alphanumeric content:
```
tr --complement --delete 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkpqrstuvwxyz0123456789' < /dev/urandom | head --bytes 48
```

> \[!CAUTION\]
> You need to reset your kanidm database after applying these patches to the kanidm source code,
> otherwise the access control profile will not be updated and any call to the new endpoint will fail!

## Provisioning (idm_)admin credentials

The second provided patch is a standalone kanidm patch that adds the ability to
specify a password when recovering account credentials. Useful to provision the
idm_admin password and avoid dynamic state that needs to be known to run the
provisioning tool.

```bash
KANIDM_RECOVER_ACCOUNT_PASSWORD=V3kACDdwPjYUgYuLdlRfBqeBWf3TyJmv9h0f6CP3E3dv2B4S \
  kanidmd recover-account idm_admin --from-environment >/dev/null
```

## JSON Schema

This is the schema consumed by this application.

Note that all keys for `groups`, `persons` and `systems.oauth2` need to be in lowercase.
E.g. `person1` is allowed, `Person1` or `pErSoN1` are not.

```yaml
{
  # Specifies the provisioned groups
  "groups": {
    # One entry per group
    "group1": {
      # Optional. Defaults to true if not given.
      # Whether the group should be present or absent.
      "present": true,
      # The exhaustive list of group members.
      "members": [
        "person1",
        "person2",
        "group1"
      ]
    },
    # ...
  },
  # Specifies the provisioned persons
  "persons": {
    # One entry per person
    "person1": {
      # Optional. Defaults to true if not given.
      # Whether the person should be present or absent.
      "present": true,
      # Required.
      "displayName": "Person1",
      # Optional.
      "legalName": "Per Son",
      # Optional.
      "mailAddresses": [
        "person1@example.com"
        # ...
      ],
    },
    # ...
  },
  "systems": {
    "oauth2": {
      # One entry per oauth2 resource server
      "forgejo": {
        # Optional. Defaults to true if not given.
        # Whether the oauth2 resource server should be present or absent.
        "present": true,
        # Optional. Defaults to false if not given.
        # Whether the oauth2 resource server should be a public one (i.e. no basic secret, enforces PKCE and can allow localhost redirect).
        "public": false,
        # Required.
        "displayName": "Forgejo",
        # Required. Must end with a '/'.
        # Also accepts a non-empty list of strings if you want to set multiple origin urls.
        # e.g. ["https://git.example.com/", "https://git.example.de/"]
        "originUrl": "https://git.example.com/",
        # Required. Landing page url (for web interface)
        "originLanding": "https://git.example.com/",
        # Optional. Only works when using the patch. Do not specify otherwise!
        # Will set the basic secret to the contents of the given file. Whitespace will be trimmed from both ends.
        # Only for non-public clients
        "basicSecretFile": "./secret1",
        # Optional. Application image to display in the WebUI.
        # Kanidm supports "image/jpeg", "image/png", "image/gif", "image/svg+xml", and "image/webp"
        # The image will be uploaded each time kanidm-provision is run
        "imageFile": "./forgejo.svg",
        # Optional. Defaults to false. Use name instead of spn for the preferred_username claim
        "preferShortUsername": false,
        # Optional. Defaults to false. Allows localhost redirects. Only for public resource servers.
        "enableLocalhostRedirects": false,
        # Optional. Defaults to false. Allows legacy jwt crypto like RS256.
        "enableLegacyCrypto": false,
        # Optional. Defaults to false. Disables PKCE for this resource server (can only be used on non-public resoure servers).
        "allowInsecureClientDisablePkce": false,
        # Optional.
        # Scope maps will map kanidm groups to returned oauth scopes.
        "scopeMaps": {
          # One entry per scope map.
          "group1": [
            "openid",
            "email",
            "profile"
          ]
        },
        # Optional.
        # Supplementary scope maps will map kanidm groups to additionally returned oauth scopes.
        "supplementaryScopeMaps": {
          # One entry per supplementary scope map. Anything not specified here will not be touched.
          # To remove an entry, assign the empty list.
          "group2": [
            "additional_scope"
          ]
        },
        # Optional. Defaults to true.
        # If true, any claim maps found on the resource server that are
        # not explicitly specified in here will be removed.
        "removeOrphanedClaimMaps": true,
        # Optional.
        # Claim maps will add a new claim with values depending on the
        # kanidm groups of the authenticating party.
        "claimMaps": {
          # One entry per claim, the key is the new claim name.
          "groups": {
            # Required.
            # The strategy used to join multiple values. One of:
            #   - "ssv" (space separated: one two three)
            #   - "csv" (comma separated: one,two,three)
            #   - "array" (array notation: ["one", "two", "three"])
            "joinType": "array",
            # Assign values based on kanidm groups.
            # At least one entry is required.
            "valuesByGroup": {
              "group1": [
                "user"
              ],
              "group2": [
                "user",
                "important_user"
              ],
              "group3": [
                "admin"
              ]
              # ...
            }
          }
          # ...
        }
      }
    }
  }
}
```

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
