# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Walnut-DNS is a Rust library that extends hickory-dns (pure Rust DNS server) with SQLite-based storage instead of zone files. It provides a complete DNS server implementation with SQLite as the authoritative data store.

## Architecture

The codebase is organized into several core modules:

- **authority/**: DNS Authority implementation with DNSSEC support, query processing, and zone management
- **database/**: SQLite-based persistence layer using monarch-db for schema management
- **client/**: DNS client implementations (UDP, HTTP/2) with connection pooling
- **server/**: Server components for handling DNS requests and responses
- **resolver/**: DNS resolution logic including hosts file and reserved address handling  
- **cache/**: Caching layer for DNS lookups and responses
- **catalog/**: Zone catalog management and storage abstraction
- **services/**: High-level service composition and configuration

Key architectural patterns:
- Trait-based abstractions for storage backends (`ZoneInfo`, `Lookup`, `CatalogStore`)
- DNSSEC integration through `DnsSecZone` wrapper
- Connection pooling with bb8 (when `pool` feature enabled)
- Flexible feature flags for different capabilities (TLS, HTTP/2, CLI tools)

## Development Commands

### Building and Testing

```bash
# Run all checks (fmt, clippy, tests, docs, security)
just all

# Basic compilation check
just check

# Run tests using nextest
just test

# Build in release mode
just build
```

### Code Quality

```bash
# Format code
just fmt-run

# Run clippy linter
just clippy

# Check unused dependencies
just udeps

# Security audit
just deny
```

### Feature Testing

```bash
# Check each feature individually
just check-hack-each

# Test feature combinations
just check-hack-powerset

# Check all target types with feature sets
just check-hack-all-targets
```

### Documentation

```bash
# Build documentation
just docs

# Build and open documentation
just read
```

### Coverage and Performance

```bash
# Run coverage analysis
just coverage

# Build with timing information
just timings
```

## Feature Flags

- `tls-ring` / `tls-aws-lc`: TLS support with different crypto backends
- `h2-ring` / `h2-aws-lc`: HTTP/2 over TLS support
- `pool`: Connection pooling with bb8
- `cli`: Command-line interface tools
- `bundled`: Use bundled SQLite (vs system SQLite)

## Binaries

The project includes three CLI tools:

- `walnut-server`: Main DNS server daemon
- `walnut`: DNS client for queries 
- `walnut-manage`: Zone and database management

## Testing

Tests are organized in the `tests/` directory with integration tests covering:
- Authority operations and DNSSEC
- Catalog management
- Server functionality
- Persistence layer

The project uses cargo-nextest for faster test execution and includes both unit tests and doctests.

## MSRV and Toolchain

- **MSRV**: Rust 1.87
- **Nightly toolchain**: nightly-2025-06-20 (for certain development tools)
- **Edition**: 2021

## Dependencies

Key external dependencies:
- **hickory-dns**: Core DNS protocol implementation
- **rusqlite**: SQLite database interface
- **monarch-db**: Database schema management
- **chateau**: Custom networking library
- **tokio**: Async runtime
- **rustls**: TLS implementation