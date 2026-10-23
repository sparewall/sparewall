# The HTTP API

`sparewall-httpd` serves the coordinator's Varlink interfaces over HTTPS,
on the management network, once the document enables it
(`management.web`). [`openapi.json`](openapi.json) describes every call:
its parameters, reply, errors, and the role it needs
(`x-sparewall-role`). It is generated from the interfaces themselves, and
a test fails when it falls behind them:

```shell
SPAREWALL_UPDATE_OPENAPI=1 cargo test -p sparewalld openapi
```

The conventions follow systemd's
[varlink-http-bridge](https://github.com/systemd/varlink-http-bridge), so
a generic Varlink-over-HTTP client works with a token.

## Calls

`POST /call/<interface>.<Method>` with the method's parameters as a JSON
object (an empty body is `{}`). The reply's parameters come back as a
JSON object with status 200.

```shell
curl -sk -H "Authorization: Bearer $TOKEN" --json '{"limit": 5}' \
    https://fw1/call/org.sparewall.Firewall.History
```

A method that streams (`Subscribe`) takes `?more=true` and answers with
an RFC 7464 JSON text sequence (`application/json-seq`): each reply is
a record (RS, JSON, LF), until the connection closes.

## Errors

An error keeps its Varlink name and parameters, with a message in words:

```json
{
  "error": "org.sparewall.Firewall.ValidationFailed",
  "parameters": {"errors": ["networks.users.vlan: expected an integer"]},
  "message": "validation failed:\n  networks.users.vlan: expected an integer"
}
```

| Status | Errors |
| --- | --- |
| 400 | `NotSupported`, `InvalidParameter`; a malformed call |
| 401 | `PermissionDenied` with role `none`: no valid credentials |
| 403 | `PermissionDenied`: the role does not allow the call |
| 404 | `NotFound`, `MethodNotFound`, `InterfaceNotFound`; `Httpd.NotFound`: no such path |
| 405 | `Httpd.MethodNotAllowed`: a call that is not a POST |
| 409 | `Conflict`, `NotPending`, `ConfirmTimeout` |
| 413 | `Httpd.TooLarge`: a request body over 4 MiB |
| 422 | `ValidationFailed` |
| 502 | `Httpd.Unavailable`: the coordinator did not answer |
| 503 | `PeerUnreachable` |
| 500 | Anything else (`ApplyFailed`) |

The `org.sparewall.Httpd` errors are the gateway's own, and have no
parameters.

The bridge answers every service error with 500 and the error as a
string; Sparewall keeps the parameters, which name the fields at fault,
and a status per error. A client that reads only `error` works with both.

## Credentials

- **Scripts** send an API token (`sparewall token create`) as
  `Authorization: Bearer <token>`.
- **Browsers** log in with `org.sparewall.Auth.Login`, which also sets
  the session in the `sparewall_session` cookie (`HttpOnly`, `Secure`,
  `SameSite=Strict`). Every request with the cookie must also carry the
  `X-Sparewall-Request` header, which a cross-site form cannot send.
  `org.sparewall.Auth.Logout` ends the session.

Each call reaches the coordinator's restricted socket bound to the
caller's token or session, and the coordinator checks it against that
role (`Bind` and `Login` need none). `sparewall-httpd` has no authority
of its own.
