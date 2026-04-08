"""
Example external check module for Keycloak Security Scanner.
Demonstrates how to implement custom checks in Python via gRPC.

Usage:
    pip install grpcio grpcio-tools requests
    python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. check_service.proto
    python server.py
"""

import grpc
from concurrent import futures
import time
import requests
import urllib3

import check_service_pb2 as pb2
import check_service_pb2_grpc as pb2_grpc

# Disable SSL warnings for self-signed certs in dev
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class KeycloakCheckModule(pb2_grpc.ExternalCheckServiceServicer):
    """Example module with two custom checks."""

    def ListChecks(self, request, context):
        """Return metadata about checks this module provides."""
        return pb2.ListChecksResponse(checks=[
            pb2.CheckMeta(
                id="CUSTOM-PY-001",
                title="Проверка количества realm-level ролей",
                description="Слишком много realm-ролей может указывать на плохую организацию RBAC",
                severity=pb2.MEDIUM,
            ),
            pb2.CheckMeta(
                id="CUSTOM-PY-002",
                title="Проверка неиспользуемых клиентов",
                description="Клиенты без активных сессий за последний период могут быть лишними",
                severity=pb2.LOW,
            ),
        ])

    def RunCheck(self, request, context):
        """Execute a check against the target Keycloak."""
        start = time.time()

        if request.check_id == "CUSTOM-PY-001":
            return self._check_realm_roles(request, start)
        elif request.check_id == "CUSTOM-PY-002":
            return self._check_unused_clients(request, start)
        else:
            return pb2.RunCheckResponse(
                check_id=request.check_id,
                status=pb2.ERROR,
                error=f"Unknown check: {request.check_id}",
                duration_ms=int((time.time() - start) * 1000),
            )

    def _get_admin_token(self, req):
        """Get admin access token from Keycloak."""
        url = f"{req.server_url}/realms/{req.realm}/protocol/openid-connect/token"
        data = {
            "grant_type": "password",
            "client_id": req.client_id,
            "username": req.username,
            "password": req.password,
        }
        resp = requests.post(url, data=data, verify=False)
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _admin_get(self, req, path):
        """Make authenticated GET request to Keycloak Admin API."""
        token = self._get_admin_token(req)
        url = f"{req.server_url}/admin/realms/{req.realm}{path}"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False)
        resp.raise_for_status()
        return resp.json()

    def _check_realm_roles(self, req, start):
        """CUSTOM-PY-001: Check if there are too many realm-level roles."""
        try:
            roles = self._admin_get(req, "/roles")
            role_count = len(roles)

            findings = []
            if role_count > 50:
                findings.append(pb2.Finding(
                    id="CUSTOM-PY-001",
                    title="Слишком много realm-level ролей",
                    description=f"Обнаружено {role_count} ролей на уровне realm. "
                                f"Большое количество ролей усложняет управление доступом и аудит.",
                    severity=pb2.MEDIUM,
                    status=pb2.DETECTED,
                    realm=req.realm,
                    evidence=[
                        pb2.Evidence(key="roleCount", value=str(role_count)),
                        pb2.Evidence(key="examples", value=", ".join(r["name"] for r in roles[:10])),
                    ],
                    recommendation="Используйте client-level роли и группы вместо большого числа realm-ролей.",
                ))

            return pb2.RunCheckResponse(
                check_id=req.check_id,
                status=pb2.DETECTED if findings else pb2.OK,
                findings=findings,
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return pb2.RunCheckResponse(
                check_id=req.check_id,
                status=pb2.ERROR,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000),
            )

    def _check_unused_clients(self, req, start):
        """CUSTOM-PY-002: Check for clients that may be unused."""
        try:
            clients = self._admin_get(req, "/clients")

            findings = []
            internal = {"account", "account-console", "admin-cli", "broker",
                        "realm-management", "security-admin-console"}

            disabled_clients = [
                c for c in clients
                if c.get("clientId") not in internal
                and not c.get("enabled", True)
            ]

            if disabled_clients:
                findings.append(pb2.Finding(
                    id="CUSTOM-PY-002",
                    title="Обнаружены отключённые клиенты",
                    description=f"{len(disabled_clients)} клиентов отключены. "
                                f"Рассмотрите их удаление для уменьшения поверхности атаки.",
                    severity=pb2.LOW,
                    status=pb2.DETECTED,
                    realm=req.realm,
                    evidence=[
                        pb2.Evidence(key="count", value=str(len(disabled_clients))),
                        pb2.Evidence(key="clients", value=", ".join(
                            c.get("clientId", "?") for c in disabled_clients[:5]
                        )),
                    ],
                    recommendation="Удалите неиспользуемые клиенты или задокументируйте причину их существования.",
                ))

            return pb2.RunCheckResponse(
                check_id=req.check_id,
                status=pb2.DETECTED if findings else pb2.OK,
                findings=findings,
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return pb2.RunCheckResponse(
                check_id=req.check_id,
                status=pb2.ERROR,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000),
            )


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb2_grpc.add_ExternalCheckServiceServicer_to_server(KeycloakCheckModule(), server)
    server.add_insecure_port("[::]:9090")
    server.start()
    print("Python check module started on port 9090")
    print("Checks available: CUSTOM-PY-001, CUSTOM-PY-002")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
