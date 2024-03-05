[About](#kanidm-secret-manipulator) \| [Usage](#usage)

## Kanidm Secret Manipulator

This is a tiny helper utility that open's kanidm's sqlite database and replaces account credentials
and/or oauth2 basic secrets token with predefined secrets loaded from a file at runtime.
This is needed to allow declarative secret provisioning in NixOS.

## Usage

Build the utility simply by running:

```bash
$ cargo build
```

Secrets are mappings are defined via a simple `mappings.json` file.
For each declarative secret, add an entry to the corresponding section,
which maps the entity name to a path where the secret can be found:

```json
{
  "account_credentials": {
    "admin": "/run/secrets/kanidm-admin-secret"
  },
  "oauth2_basic_secrets": {
    "grafana": "/run/secrets/kanidm-grafana-basic-secret",
    "forgejo": "/run/secrets/kanidm-forgejo-basic-secret"
  }
}
```

After a relevant entity (e.g. oauth2 system) is created in kanidm, stop kanidm, run the manipulator and start it again.
In NixOS this will be automated using the systemd service.
