"""Repeatable, self-contained TLS/subpath integration lab (R-scope section 10.C).

Stands up its own isolated Docker network with a Gitea server, a local TLS
terminating reverse proxy under a subpath, and a client that runs the installed
wheel. Two cases (no-token / token) confirm: exact subpath routing, six extended
requests, the synthetic token only on the version read, no auth/cookies on other
requests, local-CA verification, and no egress beyond the declared origin.

Only a local CA and a synthetic lab token are used. No production, no published
ports. Usage: python tools/tls_lab.py --wheel <wheel> --evidence-dir <dir>
"""

import argparse
import json
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

try:
    from tools.lab_cleanup import cleanup_resources
except ImportError:  # invoked as a plain script from the tools/ directory
    from lab_cleanup import cleanup_resources

GITEA_1_27_3 = (
    "docker.gitea.com/gitea@sha256:"
    "87a67ee09d3ae0d1df5fda5dcda3e2a1f9236a45b0a59025d6e00e46adc43bef"
)
PYTHON_IMAGE = (
    "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
)

PROXY_SCRIPT = r"""
import http.server, ssl, http.client, json
ALLOWED = {'/api/v1/version','/explore/repos','/v2/','/api/v1/repos/search?limit=1','/api/v1/users/search?limit=1','/'}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/forge/'):
            self.send_error(404); return
        path = self.path[len('/forge'):]
        if path not in ALLOWED:
            self.send_error(404); return
        with open('/tmp/proxy-requests.jsonl','a') as f:
            f.write(json.dumps({'path': path, 'authenticated': bool(self.headers.get('Authorization')), 'cookie': bool(self.headers.get('Cookie'))})+'\n')
        conn = http.client.HTTPConnection('SERVERNAME', 3000, timeout=5)
        headers = {}
        if self.headers.get('Authorization'):
            headers['Authorization'] = self.headers['Authorization']
        conn.request('GET', path, headers=headers)
        r = conn.getresponse(); body = r.read(262145)
        self.send_response(r.status)
        self.send_header('Content-Type', r.getheader('Content-Type','application/octet-stream'))
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Strict-Transport-Security','max-age=31536000')
        self.end_headers(); self.wfile.write(body); conn.close()
    def log_message(self, *a):
        pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/cert.pem','/tmp/key.pem')
httpd = http.server.HTTPServer(('0.0.0.0', 3443), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
"""

RUN_CLIENT = (
    "import os,sys,json,subprocess; d=json.load(sys.stdin); "
    "os.environ['FORGEGUARD_TOKEN']=d['token']; "
    "r=subprocess.run(d['args'],capture_output=True,text=True); "
    "print(json.dumps({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))"
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Isolated TLS/subpath lab; no production"
    )
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    opts = parser.parse_args()
    e = opts.evidence_dir.resolve()
    (e / "logs").mkdir(parents=True, exist_ok=True)
    prefix = "fgtls-" + uuid.uuid4().hex[:12]
    proxy_alias = "fg-tls-proxy"
    server = prefix + "-server"
    proxy = prefix + "-proxy"
    client = prefix + "-client"
    net = prefix + "-net"
    created = []

    def call(args, check=True, stdin=None):
        r = subprocess.run(
            args, capture_output=True, text=True, input=stdin, timeout=120, check=False
        )
        if check and r.returncode:
            raise RuntimeError(" ".join(args[:3]) + ": " + r.stderr[:400])
        return r

    tmp = e / (prefix + "-tls")
    tmp.mkdir(parents=True, exist_ok=True)
    call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(tmp / "key.pem"),
            "-out",
            str(tmp / "cert.pem"),
            "-days",
            "1",
            "-subj",
            "/CN=" + proxy_alias,
            "-addext",
            "subjectAltName=DNS:" + proxy_alias,
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
        ]
    )
    (tmp / "proxy.py").write_text(PROXY_SCRIPT.replace("SERVERNAME", server))

    result = {"status": "FAIL", "cases": 0}
    try:
        call(
            [
                "docker",
                "network",
                "create",
                "--internal",
                "--label",
                "forgeguard.lab=" + prefix,
                net,
            ]
        )
        created.append(("network", net))
        # Install the wheel (and its dependencies) while the client still has
        # outbound access, then move it onto the isolated internal network.
        call(
            [
                "docker",
                "run",
                "-d",
                "--name",
                client,
                "--label",
                "forgeguard.lab=" + prefix,
                "--cpus",
                "1",
                "--memory",
                "512m",
                "--pids-limit",
                "128",
                PYTHON_IMAGE,
                "sleep",
                "3600",
            ]
        )
        created.append(("container", client))
        call(
            [
                "docker",
                "cp",
                str(opts.wheel.resolve()),
                client + ":/tmp/" + opts.wheel.name,
            ]
        )
        call(
            [
                "docker",
                "exec",
                client,
                "python",
                "-m",
                "pip",
                "install",
                "/tmp/" + opts.wheel.name,
            ]
        )
        call(["docker", "cp", str(tmp / "cert.pem"), client + ":/tmp/ca.pem"])
        call(["docker", "network", "connect", net, client])
        call(["docker", "network", "disconnect", "bridge", client])
        call(
            [
                "docker",
                "run",
                "-d",
                "--name",
                proxy,
                "--label",
                "forgeguard.lab=" + prefix,
                "--network",
                net,
                "--network-alias",
                proxy_alias,
                "--cpus",
                "1",
                "--memory",
                "384m",
                "--pids-limit",
                "128",
                PYTHON_IMAGE,
                "sleep",
                "3600",
            ]
        )
        created.append(("container", proxy))
        for local, remote in [
            ("key.pem", "key.pem"),
            ("cert.pem", "cert.pem"),
            ("proxy.py", "proxy.py"),
        ]:
            call(["docker", "cp", str(tmp / local), proxy + ":/tmp/" + remote])
        call(
            [
                "docker",
                "run",
                "-d",
                "--name",
                server,
                "--label",
                "forgeguard.lab=" + prefix,
                "--network",
                net,
                "--cpus",
                "1",
                "--memory",
                "512m",
                "--pids-limit",
                "256",
                "--tmpfs",
                "/data:rw,size=384m",
                "-e",
                "GITEA__database__DB_TYPE=sqlite3",
                "-e",
                "GITEA__security__INSTALL_LOCK=true",
                "-e",
                "GITEA__server__DISABLE_SSH=true",
                "-e",
                "GITEA__service__DISABLE_REGISTRATION=true",
                "-e",
                "GITEA__service__REQUIRE_SIGNIN_VIEW=true",
                "-e",
                "GITEA__server__ROOT_URL=https://" + proxy_alias + ":3443/forge/",
                "-e",
                "GITEA__mailer__ENABLED=false",
                "-e",
                "GITEA__actions__ENABLED=false",
                GITEA_1_27_3,
            ]
        )
        created.append(("container", server))
        call(["docker", "exec", "-d", proxy, "python", "/tmp/proxy.py"])
        for _ in range(40):
            r = call(
                [
                    "docker",
                    "exec",
                    "-u",
                    "git",
                    server,
                    "gitea",
                    "admin",
                    "user",
                    "list",
                ],
                False,
            )
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("gitea did not become ready")
        call(
            [
                "docker",
                "exec",
                "-u",
                "git",
                server,
                "gitea",
                "admin",
                "user",
                "create",
                "--username",
                "synthetic-admin",
                "--random-password",
                "--email",
                "synthetic@example.invalid",
                "--admin",
            ]
        )
        token = call(
            [
                "docker",
                "exec",
                "-u",
                "git",
                server,
                "gitea",
                "admin",
                "user",
                "generate-access-token",
                "--username",
                "synthetic-admin",
                "--token-name",
                "synthetic-read",
                "--scopes",
                "read:repository",
                "--raw",
            ]
        ).stdout.strip()
        if not token or len(token) >= 256:
            raise RuntimeError("unexpected synthetic token")
        for auth in (False, True):
            args = [
                "forgeguard",
                "scan",
                "--url",
                "https://" + proxy_alias + ":3443/forge",
                "--authorized",
                "--product",
                "gitea",
                "--known-version",
                "1.27.3",
                "--profile",
                "extended",
                "--policy",
                "private",
                "--ca-bundle",
                "/tmp/ca.pem",
                "--format",
                "json",
            ]
            r = call(
                ["docker", "exec", "-i", client, "python", "-c", RUN_CLIENT],
                stdin=json.dumps({"token": token if auth else "", "args": args}),
            )
            if token in r.stdout:
                raise RuntimeError("token leaked into output")
            wrapped = json.loads(r.stdout)
            report = json.loads(wrapped["stdout"])
            assert report["identity"]["normalized_version"] == "1.27.3", "version"
            assert report["request_count"] == 6, "extended budget"
            http = next(f for f in report["findings"] if f["id"] == "FG-HTTP")
            assert all(o.get("https") for o in http["observed"].values()), (
                "non-https observed"
            )
            (e / "logs" / ("tls-subpath-" + str(auth) + ".json")).write_text(
                json.dumps(report, indent=2)
            )
        req = json.loads(
            "["
            + call(["docker", "exec", proxy, "cat", "/tmp/proxy-requests.jsonl"])
            .stdout.strip()
            .replace("\n", ",")
            + "]"
        )
        assert len(req) == 12, "expected 12 requests (6 per case)"
        assert sum(x["authenticated"] for x in req) == 1, (
            "token must appear exactly once"
        )
        assert all(
            (not x["authenticated"]) or x["path"] == "/api/v1/version" for x in req
        ), "token only on version read"
        assert not any(x["cookie"] for x in req), "no cookies sent"
        result = {
            "status": "PASS",
            "cases": 2,
            "requests": req,
            "scope": "Real Gitea 1.27.3 behind a controlled local TLS/subpath reverse proxy; local CA verified; synthetic lab token only; token on the version read only; no cookies elsewhere.",
        }
        print("TLS_SUBPATH_TOKEN=PASS")
    finally:

        def _run(args):
            r = subprocess.run(
                args, capture_output=True, text=True, check=False, timeout=60
            )
            return r.returncode, r.stderr

        cleanup = cleanup_resources(created, _run)
        cleanup["at_utc"] = datetime.now(UTC).isoformat()
        cleanup["run_prefix"] = prefix
        (e / "cleanup").mkdir(parents=True, exist_ok=True)
        (e / "cleanup" / "tls-cleanup.json").write_text(json.dumps(cleanup, indent=2))
        (e / "TLS_SUBPATH_MATRIX.json").write_text(json.dumps(result, indent=2))
    return 0 if (result["status"] == "PASS" and cleanup["status"] == "PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
