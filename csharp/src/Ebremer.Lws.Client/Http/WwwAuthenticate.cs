// SPDX-License-Identifier: MIT
using System.Collections.ObjectModel;
using System.Text;

namespace Ebremer.Lws.Http;

/// <summary>
/// One challenge from a <c>WWW-Authenticate</c> header (RFC 9110 section 11.6.1).
/// </summary>
public sealed record AuthChallenge
{
    /// <summary>Creates a challenge.</summary>
    /// <param name="scheme">The authentication scheme as sent (compare case-insensitively).</param>
    /// <param name="parameters">Auth-params; names are lower-cased.</param>
    /// <param name="token68">The token68 credential form, or null.</param>
    public AuthChallenge(string scheme, IReadOnlyDictionary<string, string>? parameters = null, string? token68 = null)
    {
        Scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));
        var p = new OrderedDictionary<string, string>(StringComparer.Ordinal);
        if (parameters is not null)
        {
            foreach (KeyValuePair<string, string> kv in parameters) p.TryAdd(kv.Key.ToLowerInvariant(), kv.Value);
        }
        Parameters = new ReadOnlyDictionary<string, string>(p);
        Token68 = token68;
    }

    /// <summary>The authentication scheme as sent.</summary>
    public string Scheme { get; }

    /// <summary>The auth-params with lower-case names and unquoted values.</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; }

    /// <summary>The token68 value, when the challenge uses that form.</summary>
    public string? Token68 { get; }

    /// <summary>LWS: the authorization server issuer (<c>as_uri</c>).</summary>
    public string? AsUri => GetParameter("as_uri");

    /// <summary>LWS: the protection scope (<c>realm</c>).</summary>
    public string? Realm => GetParameter("realm");

    /// <summary>The <c>error</c> parameter (e.g. <c>invalid_token</c>).</summary>
    public string? Error => GetParameter("error");

    /// <summary>The <c>error_description</c> parameter.</summary>
    public string? ErrorDescription => GetParameter("error_description");

    /// <summary>Whether the scheme equals <paramref name="scheme"/>, ignoring case.</summary>
    /// <param name="scheme">A scheme name.</param>
    /// <returns>Whether it matches.</returns>
    public bool IsScheme(string scheme) => string.Equals(Scheme, scheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>A parameter by (case-insensitive) name, or null.</summary>
    /// <param name="name">The parameter name.</param>
    /// <returns>The value.</returns>
    public string? GetParameter(string name) =>
        Parameters.TryGetValue(name.ToLowerInvariant(), out string? v) ? v : null;

    /// <inheritdoc/>
    public bool Equals(AuthChallenge? other) =>
        other is not null && Scheme == other.Scheme && Token68 == other.Token68
        && Parameters.Count == other.Parameters.Count
        && Parameters.All(p => other.Parameters.TryGetValue(p.Key, out string? v) && v == p.Value);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Scheme, Token68, Parameters.Count);
}

/// <summary>Parser for <c>WWW-Authenticate</c> header fields, including several challenges per field line.</summary>
public static class WwwAuthenticate
{
    /// <summary>Parses every challenge of the given field lines, in order.</summary>
    /// <param name="fieldValues">The field lines.</param>
    /// <returns>The challenges.</returns>
    public static IReadOnlyList<AuthChallenge> Parse(IEnumerable<string>? fieldValues)
    {
        var output = new List<AuthChallenge>();
        if (fieldValues is null) return output;
        foreach (string v in fieldValues)
        {
            if (v is not null) new Parser(v).ParseInto(output);
        }
        return output.AsReadOnly();
    }

    /// <summary>Parses a single field line.</summary>
    /// <param name="fieldValue">The field line.</param>
    /// <returns>The challenges.</returns>
    public static IReadOnlyList<AuthChallenge> Parse(string? fieldValue) => Parse(fieldValue is null ? [] : [fieldValue]);

    private sealed class Parser(string s)
    {
        private int _i;

        public void ParseInto(List<AuthChallenge> output)
        {
            while (true)
            {
                while (_i < s.Length && (IsWs(s[_i]) || s[_i] == ',')) _i++;
                if (_i >= s.Length) return;
                string scheme = Token();
                if (scheme.Length == 0)
                {
                    _i++;
                    continue;
                }
                SkipWs();
                int afterScheme = _i;
                string t68 = Token68();
                if (t68.Length > 0)
                {
                    SkipWs();
                    if (_i >= s.Length || s[_i] == ',')
                    {
                        output.Add(new AuthChallenge(scheme, null, t68));
                        continue;
                    }
                }
                _i = afterScheme;
                var parameters = new OrderedDictionary<string, string>(StringComparer.Ordinal);
                ParseParams(parameters);
                output.Add(new AuthChallenge(scheme, parameters));
            }
        }

        private void ParseParams(OrderedDictionary<string, string> parameters)
        {
            while (true)
            {
                SkipWs();
                int save = _i;
                string name = Token();
                if (name.Length == 0)
                {
                    _i = save;
                    return;
                }
                SkipWs();
                if (_i >= s.Length || s[_i] != '=')
                {
                    _i = save;
                    return;
                }
                _i++;
                SkipWs();
                string value = _i < s.Length && s[_i] == '"' ? Quoted() : Token();
                parameters.TryAdd(name.ToLowerInvariant(), value);
                SkipWs();
                if (_i < s.Length && s[_i] == ',')
                {
                    _i++;
                    SkipWs();
                    while (_i < s.Length && s[_i] == ',')
                    {
                        _i++;
                        SkipWs();
                    }
                    int look = _i;
                    string next = Token();
                    SkipWs();
                    bool isParam = next.Length > 0 && _i < s.Length && s[_i] == '=';
                    _i = look;
                    if (!isParam) return;
                }
                else
                {
                    return;
                }
            }
        }

        private string Token()
        {
            int start = _i;
            while (_i < s.Length && LinkHeader.IsTokenChar(s[_i])) _i++;
            return s[start.._i];
        }

        private string Token68()
        {
            int start = _i;
            while (_i < s.Length && (char.IsAsciiLetterOrDigit(s[_i]) || "-._~+/".Contains(s[_i], StringComparison.Ordinal))) _i++;
            if (_i == start) return "";
            while (_i < s.Length && s[_i] == '=') _i++;
            return s[start.._i];
        }

        private string Quoted()
        {
            var sb = new StringBuilder();
            _i++;
            while (_i < s.Length && s[_i] != '"')
            {
                if (s[_i] == '\\' && _i + 1 < s.Length)
                {
                    sb.Append(s[_i + 1]);
                    _i += 2;
                }
                else
                {
                    sb.Append(s[_i]);
                    _i++;
                }
            }
            if (_i < s.Length) _i++;
            return sb.ToString();
        }

        private void SkipWs()
        {
            while (_i < s.Length && IsWs(s[_i])) _i++;
        }

        private static bool IsWs(char c) => c is ' ' or '\t' or '\r' or '\n';
    }
}
