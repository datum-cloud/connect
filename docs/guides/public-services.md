# Publish a public HTTP service

Use public publication when an internet client must reach a local web
application. Connect sends traffic through a compatible managed gateway while
the application continues listening locally.

Public publication is an explicit opt-in. Ordinary `serve` remains private.

## Before you begin

You need a project with a compatible platform gateway and control-plane
configuration for public ingress. The local application must use TCP. Public
UDP and public services combined with `--allow` are not supported.

Because this feature is a preview, confirm the intended hostname, application
authentication, and project ownership before publishing sensitive content.

## Publish the application

If the application listens on `localhost:3000`, run:

```sh
datumctl connect serve localhost:3000 --public
```

To request a specific hostname supported by the platform configuration:

```sh
datumctl connect serve localhost:3000 --public --hostname app.example.com
```

Connect saves the service and reports its publication state. The command can
exit while the daemon continues serving it.

## Verify the publication

Inspect Connect's view first:

```sh
datumctl connect status
```

Then open the reported public URL and verify both the expected content and the
application's own access controls. A ready Connector alone does not prove that
the local application is healthy.

If publication does not become ready, check the local components without
changing them:

```sh
datumctl connect doctor
```

Also confirm that the project has a compatible gateway and transport profile.
The [headless preview guide](../headless-preview.md) contains deeper validation
and diagnostic steps.

## Remove public access

Remove the saved service by destination or by the name shown in `status`:

```sh
datumctl connect unserve localhost:3000
```

This removes the Connect publication but does not stop the local application.
Verify afterward that the public URL is no longer reachable.

If the service should remain available only to project peers, remove the public
service and create a new private service without `--public`; see
[Private services](private-services.md).
