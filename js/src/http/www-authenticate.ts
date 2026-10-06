// SPDX-License-Identifier: MIT
// WWW-Authenticate challenge parsing (RFC 9110 §11.6.1).

/** One authentication challenge. */
export class AuthChallenge {
  /** Authentication scheme as sent (compare case-insensitively). */
  readonly scheme: string;
  /** Auth parameters with lower-cased names and unquoted values. */
  readonly params: Readonly<Record<string, string>>;
  /** The token68 form, when used. */
  readonly token68: string | undefined;

  constructor(scheme: string, params: Record<string, string> = {}, token68?: string) {
    this.scheme = scheme;
    this.params = params;
    this.token68 = token68;
  }

  /** True when the scheme matches (case-insensitive). */
  is(scheme: string): boolean {
    return this.scheme.toLowerCase() === scheme.toLowerCase();
  }

  /** LWS `as_uri`: the authorization server issuer. */
  get asUri(): string | undefined {
    return this.params["as_uri"];
  }
  /** `realm`: the protection space (the access token audience). */
  get realm(): string | undefined {
    return this.params["realm"];
  }
  /** OAuth `error` code (e.g. `invalid_token`). */
  get error(): string | undefined {
    return this.params["error"];
  }
  /** OAuth `error_description`. */
  get errorDescription(): string | undefined {
    return this.params["error_description"];
  }
}

const WS = /[ \t\r\n]/;

/** Parse all challenges from one or more WWW-Authenticate header values. */
export function parseWwwAuthenticate(values: string | readonly string[] | null | undefined): AuthChallenge[] {
  if (values === null || values === undefined) return [];
  const list = typeof values === "string" ? [values] : values;
  const out: AuthChallenge[] = [];
  for (const v of list) parseInto(v, out);
  return out;
}

function parseInto(s: string, out: AuthChallenge[]): void {
  let i = 0;
  const n = s.length;
  const skipWs = (): void => {
    while (i < n && WS.test(s[i]!)) i++;
  };
  const readToken = (): string => {
    let t = "";
    while (i < n && !WS.test(s[i]!) && s[i] !== "," && s[i] !== "=") t += s[i++];
    return t;
  };
  const readQuoted = (): string => {
    let v = "";
    i++;
    while (i < n && s[i] !== '"') {
      if (s[i] === "\\" && i + 1 < n) i++;
      v += s[i++];
    }
    i++;
    return v;
  };

  while (i < n) {
    while (i < n && (WS.test(s[i]!) || s[i] === ",")) i++;
    if (i >= n) break;
    const scheme = readToken();
    if (!scheme) {
      i++;
      continue;
    }
    const params: Record<string, string> = {};
    let token68: string | undefined;
    let first = true;
    for (;;) {
      const save = i;
      while (i < n && (WS.test(s[i]!) || s[i] === ",")) i++;
      if (i >= n) break;
      const tokenStart = i;
      const token = readToken();
      if (!token) {
        // Stray character; skip it.
        i++;
        continue;
      }
      const afterToken = i;
      skipWs();
      if (s[i] === "=") {
        // Count '=' run to detect token68 ("abc==").
        let j = i;
        while (j < n && s[j] === "=") j++;
        let k = j;
        while (k < n && WS.test(s[k]!)) k++;
        const sawComma = s.slice(save, tokenStart).includes(",");
        if (first && !sawComma && (k >= n || s[k] === ",") && (j - i > 1 || afterToken === i)) {
          token68 = token + s.slice(i, j);
          i = j;
          break;
        }
        i++;
        skipWs();
        const value = s[i] === '"' ? readQuoted() : readToken();
        const name = token.toLowerCase();
        if (!(name in params)) params[name] = value;
        first = false;
      } else {
        // A bare token: token68 directly after the scheme, otherwise a new challenge.
        const sawComma = s.slice(save, tokenStart).includes(",");
        if (first && !sawComma && (i >= n || s[i] === ",")) {
          token68 = token;
          break;
        }
        i = save;
        break;
      }
    }
    out.push(new AuthChallenge(scheme, params, token68));
  }
}
