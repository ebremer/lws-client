# SPDX-License-Identifier: MIT
"""Self-signed identities (lws10-authn-ssi-cid) for bots and server-side agents.

Two options:

* ``did:key`` — the identifier *is* the public key; nothing to publish.
* An HTTPS agent URI — publish a controlled identifier document listing the key at that URI.

    python examples/self_signed_identity.py [key.json]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from lws_client import (
    SelfSignedCredentials,
    SigningKey,
    TokenExchangeAuthenticator,
    controlled_identifier_document,
)


def load_or_create_key(path: Path) -> SigningKey:
    if path.exists():
        return SigningKey.from_jwk(json.loads(path.read_text()))
    key = SigningKey.generate("ES256")
    path.write_text(json.dumps(key.private_jwk(), indent=2))  # keep this file secret!
    return key


def main() -> None:
    key = load_or_create_key(Path(sys.argv[1] if len(sys.argv) > 1 else "agent-key.json"))

    # Option 1: did:key
    did_creds = SelfSignedCredentials.did_key(key)
    print("did:key agent:", did_creds.agent)
    print("kid:          ", did_creds.kid)
    print("sample credential:", did_creds.create_token("https://as.example")[:60], "...")

    # Option 2: an HTTPS agent with a published controlled identifier document
    agent = "https://bot.example/agent"
    https_creds = SelfSignedCredentials.for_agent(agent, key, kid=f"{agent}#key-1")
    cid = controlled_identifier_document(agent, key.public_jwk(), f"{agent}#key-1")
    print(f"publish this at {agent} (application/cid+json):")
    print(json.dumps(cid, indent=2))

    # Either credential plugs into the LWS token-exchange authenticator:
    TokenExchangeAuthenticator(did_creds)
    TokenExchangeAuthenticator(https_creds)


if __name__ == "__main__":
    main()
