# Restrictive DNS Resolver

A simple DNS resolver server, resolves DNS queries based on local mappings and an optional whitelist for external queries.

## Features

- Resolves DNS queries based on `dns_records.txt`.
- Queries external DNS for domains only in in `whitelist.txt`.
- Supports UDP protocol.

## Usage

- dig @localhost -p 5333 google.com
- dig @localhost -p 5333 one.test.
