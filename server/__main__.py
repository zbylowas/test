import argparse
import sys
import uuid

import uvicorn

from server.access import change_token, provision

parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="action", required=True)
serve = sub.add_parser("serve")
serve.add_argument("--host", default="127.0.0.1")
serve.add_argument("--port", type=int, required=True)
serve.add_argument("--cert")
serve.add_argument("--key")
issue = sub.add_parser("issue-token")
issue.add_argument("tenant", type=uuid.UUID)
issue.add_argument("role", choices=["client", "operator"])
for name in ("rotate-token", "revoke-token"):
    sub.add_parser(name).add_argument("principal", type=uuid.UUID)
args = parser.parse_args()
if args.action == "serve":
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be used together")
    uvicorn.run(
        "server.api:app",
        host=args.host,
        port=args.port,
        proxy_headers=False,
        ssl_certfile=args.cert,
        ssl_keyfile=args.key,
        access_log=False,
        limit_concurrency=128,
        timeout_keep_alive=5,
    )
elif args.action == "issue-token":
    principal, token = provision(args.tenant, args.role)
    print(f"principal={principal}", file=sys.stderr)
    print(token)
else:
    token = change_token(args.principal, args.action == "rotate-token")
    if token:
        print(token)
