// SPDX-License-Identifier: MIT
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace Ebremer.Lws.Http;

/// <summary>
/// A dictionary or list member of a structured field (RFC 8941 / RFC 9651): an <see cref="SfItem"/> or an
/// <see cref="SfInnerList"/>, with parameters.
/// </summary>
/// <remarks>
/// Bare items are represented as: integer → <see cref="long"/>, decimal → <see cref="decimal"/>, string →
/// <see cref="string"/>, token → <see cref="SfToken"/>, byte sequence → <see cref="SfByteSequence"/>, boolean →
/// <see cref="bool"/>, date → <see cref="SfDate"/>, display string → <see cref="SfDisplayString"/>.
/// </remarks>
public abstract class SfMember
{
    private protected SfMember(IReadOnlyDictionary<string, object>? parameters) => Parameters = StructuredFields.Freeze(parameters);

    /// <summary>The member's parameters, in order.</summary>
    public IReadOnlyDictionary<string, object> Parameters { get; }
}

/// <summary>An item: a bare item with parameters.</summary>
public sealed class SfItem : SfMember
{
    /// <summary>Creates an item.</summary>
    /// <param name="value">The bare item value.</param>
    /// <param name="parameters">The parameters.</param>
    public SfItem(object value, IReadOnlyDictionary<string, object>? parameters = null)
        : base(parameters) => Value = value ?? throw new ArgumentNullException(nameof(value));

    /// <summary>The bare item value.</summary>
    public object Value { get; }

    /// <inheritdoc/>
    public override string ToString() => StructuredFields.Serialize(this);
}

/// <summary>An inner list of items, with parameters.</summary>
public sealed class SfInnerList : SfMember
{
    /// <summary>Creates an inner list.</summary>
    /// <param name="items">The items.</param>
    /// <param name="parameters">The parameters of the list.</param>
    public SfInnerList(IEnumerable<SfItem> items, IReadOnlyDictionary<string, object>? parameters = null)
        : base(parameters) => Items = (items ?? throw new ArgumentNullException(nameof(items))).ToList().AsReadOnly();

    /// <summary>The items.</summary>
    public IReadOnlyList<SfItem> Items { get; }

    /// <inheritdoc/>
    public override string ToString() => StructuredFields.Serialize(this);
}

/// <summary>An sf-token bare item.</summary>
/// <param name="Value">The token.</param>
public readonly record struct SfToken(string Value)
{
    /// <inheritdoc/>
    public override string ToString() => Value;
}

/// <summary>An sf-date bare item (RFC 9651): seconds since the epoch.</summary>
/// <param name="EpochSeconds">The date.</param>
public readonly record struct SfDate(long EpochSeconds);

/// <summary>An sf-displaystring bare item (RFC 9651).</summary>
/// <param name="Value">The Unicode text.</param>
public readonly record struct SfDisplayString(string Value);

/// <summary>An sf-binary (byte sequence) bare item.</summary>
public sealed class SfByteSequence : IEquatable<SfByteSequence>
{
    private readonly byte[] _value;

    /// <summary>Creates a byte sequence.</summary>
    /// <param name="value">The bytes (copied).</param>
    public SfByteSequence(ReadOnlySpan<byte> value) => _value = value.ToArray();

    /// <summary>The bytes.</summary>
    public ReadOnlyMemory<byte> Value => _value;

    /// <summary>A copy of the bytes.</summary>
    /// <returns>The bytes.</returns>
    public byte[] ToArray() => (byte[])_value.Clone();

    /// <inheritdoc/>
    public bool Equals(SfByteSequence? other) => other is not null && _value.AsSpan().SequenceEqual(other._value);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as SfByteSequence);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(_value);
        return h.ToHashCode();
    }

    /// <inheritdoc/>
    public override string ToString() => ":" + Convert.ToBase64String(_value) + ":";
}

/// <summary>Input that is not a valid structured field.</summary>
public sealed class StructuredFieldFormatException : FormatException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What is wrong.</param>
    public StructuredFieldFormatException(string message) : base(message)
    {
    }
}

/// <summary>
/// Structured Field Values (RFC 8941 / RFC 9651): dictionaries, lists, items, inner lists and parameters, as used
/// by <c>Signature-Input</c>, <c>Signature</c> and <c>Content-Digest</c>.
/// </summary>
public static class StructuredFields
{
    internal static IReadOnlyDictionary<string, object> Freeze(IReadOnlyDictionary<string, object>? parameters)
    {
        var p = new OrderedDictionary<string, object>(StringComparer.Ordinal);
        if (parameters is not null)
        {
            foreach (KeyValuePair<string, object> kv in parameters) p[kv.Key] = kv.Value;
        }
        return new ReadOnlyDictionary<string, object>(p);
    }

    /// <summary>Parses a dictionary (RFC 8941 section 4.2.2). Join several field lines with <c>", "</c> first.</summary>
    /// <param name="input">The field value.</param>
    /// <returns>The members in order (a repeated key keeps its first position and takes the last value).</returns>
    /// <exception cref="StructuredFieldFormatException">The input is not a valid dictionary.</exception>
    public static IReadOnlyDictionary<string, SfMember> ParseDictionary(string input)
    {
        var p = new Parser(input ?? throw new ArgumentNullException(nameof(input)));
        p.SkipSp();
        var dict = p.Dictionary();
        p.SkipSp();
        if (!p.Eof) throw new StructuredFieldFormatException("Trailing characters in structured field");
        return new ReadOnlyDictionary<string, SfMember>(dict);
    }

    /// <summary>Parses a list (RFC 8941 section 4.2.1).</summary>
    /// <param name="input">The field value.</param>
    /// <returns>The members.</returns>
    /// <exception cref="StructuredFieldFormatException">The input is not a valid list.</exception>
    public static IReadOnlyList<SfMember> ParseList(string input)
    {
        var p = new Parser(input ?? throw new ArgumentNullException(nameof(input)));
        p.SkipSp();
        var output = new List<SfMember>();
        while (!p.Eof)
        {
            output.Add(p.ItemOrInnerList());
            p.SkipOws();
            if (p.Eof) break;
            p.Expect(',');
            p.SkipOws();
            if (p.Eof) throw new StructuredFieldFormatException("Trailing comma in list");
        }
        return output.AsReadOnly();
    }

    /// <summary>Parses an item (RFC 8941 section 4.2.3).</summary>
    /// <param name="input">The field value.</param>
    /// <returns>The item.</returns>
    /// <exception cref="StructuredFieldFormatException">The input is not a valid item.</exception>
    public static SfItem ParseItem(string input)
    {
        var p = new Parser(input ?? throw new ArgumentNullException(nameof(input)));
        p.SkipSp();
        SfItem item = p.Item();
        p.SkipSp();
        if (!p.Eof) throw new StructuredFieldFormatException("Trailing characters in structured field");
        return item;
    }

    private sealed class Parser(string s)
    {
        private int _i;

        public bool Eof => _i >= s.Length;

        private char Peek() => s[_i];

        public void Expect(char c)
        {
            if (Eof || s[_i] != c) throw new StructuredFieldFormatException($"Expected '{c}' at {_i}");
            _i++;
        }

        public void SkipSp()
        {
            while (!Eof && s[_i] == ' ') _i++;
        }

        public void SkipOws()
        {
            while (!Eof && (s[_i] == ' ' || s[_i] == '\t')) _i++;
        }

        public OrderedDictionary<string, SfMember> Dictionary()
        {
            var dict = new OrderedDictionary<string, SfMember>(StringComparer.Ordinal);
            while (!Eof)
            {
                string key = Key();
                SfMember member;
                if (!Eof && Peek() == '=')
                {
                    _i++;
                    member = ItemOrInnerList();
                }
                else
                {
                    member = new SfItem(true, Parameters());
                }
                dict[key] = member;
                SkipOws();
                if (Eof) break;
                Expect(',');
                SkipOws();
                if (Eof) throw new StructuredFieldFormatException("Trailing comma in dictionary");
            }
            return dict;
        }

        public SfMember ItemOrInnerList() => !Eof && Peek() == '(' ? InnerList() : Item();

        private SfInnerList InnerList()
        {
            Expect('(');
            var items = new List<SfItem>();
            while (!Eof)
            {
                SkipSp();
                if (Eof) break;
                if (Peek() == ')')
                {
                    _i++;
                    return new SfInnerList(items, Parameters());
                }
                items.Add(Item());
                if (Eof) break;
                char c = Peek();
                if (c != ' ' && c != ')') throw new StructuredFieldFormatException($"Invalid inner list at {_i}");
            }
            throw new StructuredFieldFormatException("Unterminated inner list");
        }

        public SfItem Item()
        {
            object bare = BareItem();
            return new SfItem(bare, Parameters());
        }

        private OrderedDictionary<string, object> Parameters()
        {
            var parameters = new OrderedDictionary<string, object>(StringComparer.Ordinal);
            while (!Eof && Peek() == ';')
            {
                _i++;
                SkipSp();
                string key = Key();
                object value = true;
                if (!Eof && Peek() == '=')
                {
                    _i++;
                    value = BareItem();
                }
                parameters[key] = value;
            }
            return parameters;
        }

        private string Key()
        {
            if (Eof) throw new StructuredFieldFormatException("Expected a key");
            char c = Peek();
            if (c is not (>= 'a' and <= 'z') && c != '*') throw new StructuredFieldFormatException($"Invalid key at {_i}");
            int start = _i;
            while (!Eof)
            {
                c = Peek();
                if (c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-' or '.' or '*') _i++;
                else break;
            }
            return s[start.._i];
        }

        private object BareItem()
        {
            if (Eof) throw new StructuredFieldFormatException("Expected a bare item");
            char c = Peek();
            if (c == '-' || c is >= '0' and <= '9') return Number();
            if (c == '"') return String();
            if (c == '*' || c is >= 'a' and <= 'z' or >= 'A' and <= 'Z') return Token();
            if (c == ':') return Bytes();
            if (c == '?') return Boolean();
            if (c == '@')
            {
                _i++;
                return Number() is long l ? new SfDate(l) : throw new StructuredFieldFormatException("A date must be an integer");
            }
            if (c == '%') return DisplayString();
            throw new StructuredFieldFormatException($"Unexpected character '{c}' at {_i}");
        }

        private object Number()
        {
            int start = _i;
            if (Peek() == '-') _i++;
            if (Eof || Peek() is not (>= '0' and <= '9')) throw new StructuredFieldFormatException($"Expected a digit at {_i}");
            bool isDecimal = false;
            int digitsStart = _i;
            int intDigits = -1;
            while (!Eof)
            {
                char c = Peek();
                if (c is >= '0' and <= '9')
                {
                    _i++;
                }
                else if (c == '.' && !isDecimal)
                {
                    intDigits = _i - digitsStart;
                    if (intDigits > 12) throw new StructuredFieldFormatException("Decimal integer part too long");
                    isDecimal = true;
                    _i++;
                }
                else
                {
                    break;
                }
                int len = _i - digitsStart;
                if (!isDecimal && len > 15) throw new StructuredFieldFormatException("Integer too long");
                if (isDecimal && len > 16) throw new StructuredFieldFormatException("Decimal too long");
            }
            string num = s[start.._i];
            if (!isDecimal) return long.Parse(num, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            if (num.EndsWith('.')) throw new StructuredFieldFormatException("Decimal ends with '.'");
            int frac = _i - digitsStart - intDigits - 1;
            if (frac > 3) throw new StructuredFieldFormatException("Decimal fraction too long");
            return decimal.Parse(num, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
        }

        private string String()
        {
            Expect('"');
            var sb = new StringBuilder();
            while (!Eof)
            {
                char c = s[_i++];
                if (c == '\\')
                {
                    if (Eof) throw new StructuredFieldFormatException("Unterminated escape");
                    char n = s[_i++];
                    if (n != '"' && n != '\\') throw new StructuredFieldFormatException("Invalid escape");
                    sb.Append(n);
                }
                else if (c == '"')
                {
                    return sb.ToString();
                }
                else if (c < 0x20 || c > 0x7e)
                {
                    throw new StructuredFieldFormatException("Invalid string character");
                }
                else
                {
                    sb.Append(c);
                }
            }
            throw new StructuredFieldFormatException("Unterminated string");
        }

        private SfToken Token()
        {
            int start = _i;
            _i++;
            while (!Eof && (LinkHeader.IsTokenChar(Peek()) || Peek() == ':' || Peek() == '/')) _i++;
            return new SfToken(s[start.._i]);
        }

        private SfByteSequence Bytes()
        {
            Expect(':');
            int end = s.IndexOf(':', _i);
            if (end < 0) throw new StructuredFieldFormatException("Unterminated byte sequence");
            string b64 = s[_i..end];
            foreach (char c in b64)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || c == '+' || c == '/' || c == '=')) throw new StructuredFieldFormatException("Invalid base64 in byte sequence");
            }
            _i = end + 1;
            try
            {
                return new SfByteSequence(Convert.FromBase64String(b64));
            }
            catch (FormatException)
            {
                throw new StructuredFieldFormatException("Invalid base64 in byte sequence");
            }
        }

        private bool Boolean()
        {
            Expect('?');
            if (Eof) throw new StructuredFieldFormatException("Expected a boolean");
            char c = s[_i++];
            return c switch
            {
                '1' => true,
                '0' => false,
                _ => throw new StructuredFieldFormatException("Invalid boolean"),
            };
        }

        private SfDisplayString DisplayString()
        {
            Expect('%');
            Expect('"');
            var bytes = new List<byte>();
            while (!Eof)
            {
                char c = s[_i++];
                if (c == '%')
                {
                    if (_i + 2 > s.Length) throw new StructuredFieldFormatException("Invalid percent-encoding");
                    string hex = s.Substring(_i, 2);
                    if (!hex.All(h => h is >= '0' and <= '9' or >= 'a' and <= 'f')) throw new StructuredFieldFormatException("Invalid percent-encoding");
                    bytes.Add(byte.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                    _i += 2;
                }
                else if (c == '"')
                {
                    try
                    {
                        return new SfDisplayString(new UTF8Encoding(false, true).GetString(bytes.ToArray()));
                    }
                    catch (DecoderFallbackException)
                    {
                        throw new StructuredFieldFormatException("Invalid UTF-8 in display string");
                    }
                }
                else if (c < 0x20 || c > 0x7e)
                {
                    throw new StructuredFieldFormatException("Invalid display string character");
                }
                else
                {
                    bytes.Add((byte)c);
                }
            }
            throw new StructuredFieldFormatException("Unterminated display string");
        }
    }

    /// <summary>Serializes a member (an item or an inner list, with parameters) canonically.</summary>
    /// <param name="member">The member.</param>
    /// <returns>The serialization, e.g. <c>("@method" "@path");created=1;keyid="k"</c>.</returns>
    public static string Serialize(SfMember member)
    {
        ArgumentNullException.ThrowIfNull(member);
        var sb = new StringBuilder();
        if (member is SfInnerList list)
        {
            sb.Append('(');
            for (int i = 0; i < list.Items.Count; i++)
            {
                if (i > 0) sb.Append(' ');
                SerializeItem(list.Items[i], sb);
            }
            sb.Append(')');
            SerializeParameters(list.Parameters, sb);
        }
        else
        {
            SerializeItem((SfItem)member, sb);
        }
        return sb.ToString();
    }

    /// <summary>Serializes a dictionary canonically.</summary>
    /// <param name="dictionary">The members.</param>
    /// <returns>The serialization.</returns>
    public static string SerializeDictionary(IEnumerable<KeyValuePair<string, SfMember>> dictionary)
    {
        ArgumentNullException.ThrowIfNull(dictionary);
        var sb = new StringBuilder();
        foreach (KeyValuePair<string, SfMember> e in dictionary)
        {
            if (sb.Length > 0) sb.Append(", ");
            sb.Append(e.Key);
            if (e.Value is SfItem { Value: true } item)
            {
                SerializeParameters(item.Parameters, sb);
            }
            else
            {
                sb.Append('=').Append(Serialize(e.Value));
            }
        }
        return sb.ToString();
    }

    private static void SerializeItem(SfItem item, StringBuilder sb)
    {
        sb.Append(SerializeBareItem(item.Value));
        SerializeParameters(item.Parameters, sb);
    }

    private static void SerializeParameters(IReadOnlyDictionary<string, object> parameters, StringBuilder sb)
    {
        foreach (KeyValuePair<string, object> p in parameters)
        {
            sb.Append(';').Append(p.Key);
            if (p.Value is not true) sb.Append('=').Append(SerializeBareItem(p.Value));
        }
    }

    /// <summary>Serializes a bare item.</summary>
    /// <param name="value">The value (see <see cref="SfMember"/> for the type mapping).</param>
    /// <returns>The serialization.</returns>
    /// <exception cref="ArgumentException">The value is not a bare item.</exception>
    public static string SerializeBareItem(object value)
    {
        switch (value)
        {
            case long or int or short:
                return Convert.ToString(value, CultureInfo.InvariantCulture)!;
            case decimal d:
                {
                    decimal r = Math.Round(d, 3, MidpointRounding.ToEven);
                    return r.ToString("0.0##", CultureInfo.InvariantCulture);
                }
            case string str:
                return Quote(str);
            case SfToken t:
                return t.Value;
            case SfByteSequence b:
                return b.ToString();
            case byte[] raw:
                return ":" + Convert.ToBase64String(raw) + ":";
            case bool flag:
                return flag ? "?1" : "?0";
            case SfDate date:
                return "@" + date.EpochSeconds.ToString(CultureInfo.InvariantCulture);
            case SfDisplayString ds:
                {
                    var sb = new StringBuilder("%\"");
                    foreach (byte b in Encoding.UTF8.GetBytes(ds.Value))
                    {
                        if (b == '%' || b == '"' || b < 0x20 || b > 0x7e) sb.Append('%').Append(b.ToString("x2", CultureInfo.InvariantCulture));
                        else sb.Append((char)b);
                    }
                    return sb.Append('"').ToString();
                }
            default:
                throw new ArgumentException($"Not a structured field bare item: {value}", nameof(value));
        }
    }

    private static string Quote(string str)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in str)
        {
            if (c < 0x20 || c > 0x7e) throw new ArgumentException("Invalid character in an sf-string", nameof(str));
            if (c == '"' || c == '\\') sb.Append('\\');
            sb.Append(c);
        }
        return sb.Append('"').ToString();
    }
}
