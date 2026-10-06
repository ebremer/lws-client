# SPDX-License-Identifier: MIT
"""Receive and verify LWS webhook notifications (RFC 9421 signed deliveries).

Starts an inbox on http://127.0.0.1:9090/inbox, subscribes to a container, makes a change
and prints the verified notification.

    python examples/webhook_receiver.py http://localhost:8787/root/
"""

from __future__ import annotations

import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lws_client import (
    LwsClient,
    SelfSignedCredentials,
    SignatureVerificationError,
    SigningKey,
    TokenExchangeAuthenticator,
    VerifiedNotification,
    WebhookVerifier,
)

INBOX = "http://127.0.0.1:9090/inbox"


def serve_inbox(verifier: WebhookVerifier, out: queue.Queue[VerifiedNotification]) -> ThreadingHTTPServer:
    class Inbox(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            try:
                # Verify against the *registered* inbox URL, not the Host header.
                verified = verifier.verify("POST", INBOX, list(self.headers.items()), body)
            except SignatureVerificationError as exc:
                print("rejected delivery:", exc)
                self.send_response(401)
            else:
                out.put(verified)
                self.send_response(204)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 9090), Inbox)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main(resource_url: str) -> None:
    credentials = SelfSignedCredentials.did_key(SigningKey.generate())
    with LwsClient(authenticator=TokenExchangeAuthenticator(credentials)) as client:
        storage = client.discover_storage(resource_url)
        verifier = WebhookVerifier(client=client, trusted_storages=[storage.id])
        received: queue.Queue[VerifiedNotification] = queue.Queue()
        server = serve_inbox(verifier, received)
        try:
            folder = client.create_container(storage.storage_root(), slug="watched")
            service = storage.service("NotificationService")
            if service is None:
                raise SystemExit("this storage does not offer notifications")
            subscription = client.subscribe(service, [folder.location], INBOX)
            print("subscribed:", subscription.subscription)

            client.create_text(folder.location, "hello", slug="hello.txt")
            verified = received.get(timeout=10)
            for activity in verified.notification.activities:
                print(f"{activity.types} {activity.object.id} at {activity.published_raw} "
                      f"(signed by {verified.keyid})")

            client.unsubscribe(subscription)
            client.delete(folder.location, recursive=True)
        finally:
            server.shutdown()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787/root/")
