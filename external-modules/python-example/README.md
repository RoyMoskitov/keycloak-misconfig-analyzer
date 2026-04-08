# Python External Check Module

Example external module that adds custom Keycloak security checks via gRPC.

## Setup

```bash
pip install grpcio grpcio-tools requests

# Generate Python gRPC code from proto
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. check_service.proto

# Run the module
python server.py
```

## Configure main scanner

In `application.yml`:
```yaml
scanner:
  external:
    modules:
      - name: python-checks
        host: localhost
        port: 9090
```

## Checks provided

- **CUSTOM-PY-001** — Too many realm-level roles (>50)
- **CUSTOM-PY-002** — Disabled/unused clients
