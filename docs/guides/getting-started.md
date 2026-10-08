# Getting started

This walkthrough connects a device to a Datum project, shares a local web
application privately, and reaches it from a second device.

## Before you begin

You need:

- a supported macOS or Linux host;
- `datumctl` signed in to a Datum environment and project;
- the trusted Connect plugin; and
- a local TCP application to share.

Follow [Install the preview](../INSTALL.txt) if the plugin is not installed.
Interactive `serve` can guide daemon installation and first enrollment on macOS
and Linux. Scripts, JSON/YAML output, explicit daemon tokens, custom daemon
URLs, Windows, and root sessions must run explicit setup and `up` first.

## 1. Start a local application

For this example, assume an application is listening on `localhost:8080`. Keep
it bound to loopback; Connect does not require it to listen on every interface.

## 2. Share the service

On the device running the application:

```sh
datumctl connect serve localhost:8080
```

Complete any prompts for installation, login, project selection, or first
enrollment. The result includes the Connector name and a command another device
can use.

When the platform advertises Connector authentication, your existing Datum
login authorizes one atomic Connector creation. The daemon generates separate
transport and authentication keys, keeps both private keys locally, and
switches to the platform-issued per-Connector credential after verifying it can
access that exact Connector. Do not delete the local daemon state: preview
identity recovery requires deleting and recreating the Connector.

Check the saved service at any time:

```sh
datumctl connect status
```

## 3. Connect the second device

Install Connect on the second device, select the same project, and connect it:

```sh
datumctl connect up
```

Create a loopback-only local forward to the serving Connector. Replace
`SERVER_CONNECTOR` with the name reported by the first device:

```sh
datumctl connect dial SERVER_CONNECTOR:8080 --bind 18080
```

Open `http://localhost:18080` or test it from the shell:

```sh
curl http://localhost:18080
```

The local application connects to port `18080`; Connect carries that traffic to
port `8080` on the serving device.

## 4. Clean up

On the consuming device, remove the local forward:

```sh
datumctl connect hangup 18080
```

On the serving device, stop sharing the service:

```sh
datumctl connect unserve localhost:8080
```

These commands do not stop the application or the Connect daemon.

The Connector itself is intentionally retained. Deleting it is a stronger
revocation operation: the platform removes its service account, authentication
key, and exact-resource authorization. The preview does not silently recreate a
deleted Connector.

## Next steps

- Add explicit access rules or UDP with [Private services](private-services.md).
- Publish a web application with [Public services](public-services.md).
- Reach private project addresses with [Project network access](project-network-access.md).
