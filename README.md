# `common`

Shared infrastructure and security utilities for all services.

## Responsibility

`common` provides reusable infrastructure:

- JWT helpers and key parsing;
- auth context utilities;
- HTTP/gRPC auth middleware;
- runtime server helpers;
- PostgreSQL connection helper;
- configuration parsing.

It contains no business logic.

## Packages

- `authsecurity`
  JWT issuer/verifier, RSA key parsing, refresh token helpers;
- `authctx`
  context helpers for authenticated user id;
- `grpcauth`
  gRPC auth interceptor;
- `httpauth`
  HTTP auth middleware;
- `runtime`
  HTTP/gRPC server helpers, timeouts, graceful shutdown;
- `postgres`
  PostgreSQL connection helper;
- `configenv`
  env parsing helpers.

## Summary

Main design choices:

- keep infrastructure in one module;
- keep services thin and explicit;
- avoid hidden frameworks or heavy abstractions.
