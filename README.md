# IQ Server Report Fetcher

## Overview

Go CLI tool to fetch latest policy violation reports from Sonatype IQ Server APIs and export as CSV. Supports organization filtering.

## Features

- Basic auth to IQ Server
- List apps, get latest build reports
- Parse violations (threat level, constraints, CVEs)
- Timestamped CSV output with atomic writes

## Prerequisites

- Go 1.21+
- IQ Server v2 API access

## Setup

1. Clone: `git clone https://github.com/anmicius0/iqserver-report-fetch-go`
2. Deps: `make install-deps`
3. Config: Copy `config/.env.example` to `config/.env`; set `IQ_SERVER_URL`, `IQ_USERNAME`, `IQ_PASSWORD`, optional `ORGANIZATION_ID`

## Usage

```bash
make run28 hidden lines
```

Generates reports_output/YYYY-MM-DD_HH-MM-SS.csv with columns: No., Application, Organization, Policy, Component, Threat, Policy/Action, Constraint Name, Condition, CVE.

## Build

```bash
bashmake build-linux-amd64  # Darwin ARM64, Windows AMD64 also available
```

## Test

```bash
make test
```

## License

MIT
