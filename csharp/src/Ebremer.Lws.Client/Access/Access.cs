// SPDX-License-Identifier: MIT
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Access;

/// <summary>
/// An ODRL constraint limiting an access policy (<c>leftOperand operator rightOperand</c>). All constraints of a policy
/// must hold.
/// </summary>
public sealed record Constraint
{
    /// <summary>Creates a constraint.</summary>
    /// <param name="leftOperand"><c>client</c>, <c>format</c>, <c>type</c>, <c>purpose</c>, <c>dateTime</c>, …</param>
    /// <param name="operator"><c>eq</c>, <c>isAnyOf</c>, <c>gteq</c>, <c>lteq</c>, …</param>
    /// <param name="rightOperand">The comparison value (a string, or an array for <c>isAnyOf</c>).</param>
    public Constraint(string leftOperand, string @operator, JsonElement rightOperand)
    {
        LeftOperand = leftOperand ?? throw new ArgumentNullException(nameof(leftOperand));
        Operator = @operator ?? throw new ArgumentNullException(nameof(@operator));
        RightOperand = rightOperand.Clone();
    }

    /// <summary>The left operand.</summary>
    public string LeftOperand { get; }

    /// <summary>The operator.</summary>
    public string Operator { get; }

    /// <summary>The right operand (raw JSON).</summary>
    public JsonElement RightOperand { get; }

    /// <summary>A constraint with any JSON right operand.</summary>
    /// <param name="leftOperand">The left operand.</param>
    /// <param name="operator">The operator.</param>
    /// <param name="rightOperand">The right operand.</param>
    /// <returns>The constraint.</returns>
    public static Constraint Of(string leftOperand, string @operator, JsonNode? rightOperand) =>
        new(leftOperand, @operator, LwsJson.ToElement(rightOperand));

    /// <summary><c>purpose eq &lt;purpose&gt;</c>.</summary>
    /// <param name="purpose">The purpose IRI.</param>
    /// <returns>The constraint.</returns>
    public static Constraint Purpose(Uri purpose) => Of(Lws.Operands.Purpose, Lws.Operators.Eq, Text(purpose));

    /// <summary><c>purpose isAnyOf [purposes]</c>.</summary>
    /// <param name="purposes">The purpose IRIs.</param>
    /// <returns>The constraint.</returns>
    public static Constraint PurposeAnyOf(IEnumerable<Uri> purposes) => Of(Lws.Operands.Purpose, Lws.Operators.IsAnyOf, Array(purposes.Select(Text)));

    /// <summary><c>client eq &lt;client&gt;</c>: restricts access to one client application.</summary>
    /// <param name="clientId">The client identifier.</param>
    /// <returns>The constraint.</returns>
    public static Constraint Client(Uri clientId) => Of(Lws.Operands.Client, Lws.Operators.Eq, Text(clientId));

    /// <summary><c>format eq &lt;mediaType&gt;</c>.</summary>
    /// <param name="mediaType">The media type.</param>
    /// <returns>The constraint.</returns>
    public static Constraint Format(string mediaType) => Of(Lws.Operands.Format, Lws.Operators.Eq, mediaType);

    /// <summary><c>format isAnyOf [mediaTypes]</c>.</summary>
    /// <param name="mediaTypes">The media types.</param>
    /// <returns>The constraint.</returns>
    public static Constraint FormatAnyOf(IEnumerable<string> mediaTypes) => Of(Lws.Operands.Format, Lws.Operators.IsAnyOf, Array(mediaTypes));

    /// <summary><c>type eq &lt;type&gt;</c>: matches the resource's <c>rel="type"</c> links.</summary>
    /// <param name="type">The type IRI.</param>
    /// <returns>The constraint.</returns>
    public static Constraint Type(Uri type) => Of(Lws.Operands.Type, Lws.Operators.Eq, Text(type));

    /// <summary><c>type isAnyOf [types]</c>.</summary>
    /// <param name="types">The type IRIs.</param>
    /// <returns>The constraint.</returns>
    public static Constraint TypeAnyOf(IEnumerable<Uri> types) => Of(Lws.Operands.Type, Lws.Operators.IsAnyOf, Array(types.Select(Text)));

    /// <summary><c>dateTime gteq &lt;instant&gt;</c>: access starts at <paramref name="instant"/>.</summary>
    /// <param name="instant">The start.</param>
    /// <returns>The constraint.</returns>
    public static Constraint NotBefore(DateTimeOffset instant) => Of(Lws.Operands.DateTime, Lws.Operators.GtEq, LwsJson.FormatDateTime(instant));

    /// <summary><c>dateTime lteq &lt;instant&gt;</c>: access ends at <paramref name="instant"/>.</summary>
    /// <param name="instant">The end.</param>
    /// <returns>The constraint.</returns>
    public static Constraint NotAfter(DateTimeOffset instant) => Of(Lws.Operands.DateTime, Lws.Operators.LtEq, LwsJson.FormatDateTime(instant));

    private static string Text(Uri u) => Uris.ToText(u ?? throw new ArgumentNullException(nameof(u)));

    private static JsonArray Array(IEnumerable<string> values) => LwsJson.StringArray(values ?? throw new ArgumentNullException(nameof(values)));

    internal JsonObject ToJson() => new()
    {
        ["leftOperand"] = LeftOperand,
        ["operator"] = Operator,
        ["rightOperand"] = LwsJson.ToNode(RightOperand),
    };

    internal static Constraint Parse(JsonElement n)
    {
        string? left = LwsJson.GetString(n, "leftOperand");
        string? op = LwsJson.GetString(n, "operator");
        JsonElement? right = LwsJson.Get(n, "rightOperand");
        if (left is null || op is null || right is null) throw new ProtocolException("Incomplete constraint");
        return new Constraint(left, op, right.Value);
    }
}

/// <summary>The resources an access policy applies to.</summary>
public sealed record AccessTarget
{
    /// <summary>Creates a target.</summary>
    /// <param name="type">The matcher: <c>StorageResource</c>, <c>Container</c>, <c>DataResource</c>, or an IRI.</param>
    /// <param name="values">The target identifiers (at least one).</param>
    public AccessTarget(string type, IEnumerable<string> values)
    {
        Type = type ?? throw new ArgumentNullException(nameof(type));
        Values = (values ?? throw new ArgumentNullException(nameof(values))).ToList().AsReadOnly();
        if (Values.Count == 0) throw new ArgumentException("An access target needs at least one value", nameof(values));
    }

    /// <summary>The matcher type.</summary>
    public string Type { get; }

    /// <summary>The target identifiers.</summary>
    public IReadOnlyList<string> Values { get; }

    /// <summary>Any storage resource among <paramref name="resources"/>.</summary>
    /// <param name="resources">The resources.</param>
    /// <returns>The target.</returns>
    public static AccessTarget StorageResources(params IEnumerable<Uri> resources) => new("StorageResource", resources.Select(Uris.ToText));

    /// <summary>The containers among <paramref name="resources"/>.</summary>
    /// <param name="resources">The resources.</param>
    /// <returns>The target.</returns>
    public static AccessTarget Containers(params IEnumerable<Uri> resources) => new("Container", resources.Select(Uris.ToText));

    /// <summary>The data resources among <paramref name="resources"/>.</summary>
    /// <param name="resources">The resources.</param>
    /// <returns>The target.</returns>
    public static AccessTarget DataResources(params IEnumerable<Uri> resources) => new("DataResource", resources.Select(Uris.ToText));

    internal JsonObject ToJson() => new() { ["type"] = Type, ["value"] = LwsJson.StringArray(Values) };

    internal static AccessTarget Parse(JsonElement n) =>
        new(LwsJson.GetString(n, "type") ?? "StorageResource", LwsJson.StringOrArray(LwsJson.Get(n, "value")));
}

/// <summary>
/// An access policy of the LWS access profile (ODRL-based): who (<see cref="Assignee"/>) may do what
/// (<see cref="Actions"/>) on which resources (<see cref="Target"/>) under which <see cref="Constraints"/>.
/// </summary>
public sealed record AccessPolicy
{
    /// <summary>Creates a policy.</summary>
    /// <param name="actions"><c>read</c>, <c>modify</c>, <c>create</c>, <c>delete</c>, … (at least one).</param>
    /// <param name="assignee">The agent (<see cref="Lws.PublicAgent"/> for public access).</param>
    /// <param name="target">The target resources.</param>
    /// <param name="constraints">The constraints (all must hold).</param>
    public AccessPolicy(IEnumerable<string> actions, string assignee, AccessTarget? target = null, IEnumerable<Constraint>? constraints = null)
        : this([Lws.Types.AccessPolicy], actions, assignee, target, constraints)
    {
    }

    private AccessPolicy(IEnumerable<string> types, IEnumerable<string> actions, string assignee, AccessTarget? target, IEnumerable<Constraint>? constraints)
    {
        Types = types.ToList().AsReadOnly();
        Actions = (actions ?? throw new ArgumentNullException(nameof(actions))).ToList().AsReadOnly();
        if (Actions.Count == 0) throw new ArgumentException("An access policy needs at least one action", nameof(actions));
        Assignee = assignee ?? throw new ArgumentNullException(nameof(assignee));
        if (!Uris.HasScheme(assignee)) throw new ArgumentException($"The assignee must be an absolute IRI: {assignee}", nameof(assignee));
        Target = target;
        Constraints = (constraints ?? []).ToList().AsReadOnly();
    }

    /// <summary>The policy types (they include <c>AccessPolicy</c>).</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The actions.</summary>
    public IReadOnlyList<string> Actions { get; }

    /// <summary>The agent the policy applies to (a URL or a DID).</summary>
    public string Assignee { get; }

    /// <summary>The target resources.</summary>
    public AccessTarget? Target { get; }

    /// <summary>The constraints.</summary>
    public IReadOnlyList<Constraint> Constraints { get; }

    internal JsonObject ToJson()
    {
        var o = new JsonObject
        {
            ["type"] = LwsJson.StringArray(Types),
            ["action"] = LwsJson.StringArray(Actions),
            ["assignee"] = Assignee,
        };
        if (Target is not null) o["target"] = Target.ToJson();
        if (Constraints.Count > 0)
        {
            var a = new JsonArray();
            foreach (Constraint c in Constraints) a.Add(c.ToJson());
            o["constraint"] = a;
        }
        return o;
    }

    internal static AccessPolicy Parse(JsonElement n)
    {
        LwsJson.RequireObject(n, "Access policy");
        string assignee = LwsJson.GetString(n, "assignee") ?? throw new ProtocolException("The access policy has no assignee");
        var constraints = new List<Constraint>();
        if (LwsJson.Get(n, "constraint") is { ValueKind: JsonValueKind.Array } cs)
        {
            foreach (JsonElement c in cs.EnumerateArray()) constraints.Add(Constraint.Parse(c));
        }
        AccessTarget? target = LwsJson.Get(n, "target") is { ValueKind: JsonValueKind.Object } t ? Wrap(() => AccessTarget.Parse(t)) : null;
        return Wrap(() => new AccessPolicy(LwsJson.StringOrArray(LwsJson.Get(n, "type")), LwsJson.StringOrArray(LwsJson.Get(n, "action")),
            assignee, target, constraints));
    }

    internal static T Wrap<T>(Func<T> build)
    {
        try
        {
            return build();
        }
        catch (ArgumentException e)
        {
            throw new ProtocolException(e.Message, e);
        }
    }
}

/// <summary>Shared structure of <see cref="AccessRequest"/> and <see cref="AccessGrant"/>.</summary>
public abstract record AccessDocument
{
    private protected AccessDocument(IEnumerable<string> types, Uri storage, Uri? inbox, IEnumerable<AccessPolicy> access, JsonElement? raw)
    {
        Types = types.ToList().AsReadOnly();
        Storage = storage ?? throw new ArgumentNullException(nameof(storage));
        Inbox = inbox;
        Access = (access ?? throw new ArgumentNullException(nameof(access))).ToList().AsReadOnly();
        if (Access.Count == 0) throw new ArgumentException("At least one access policy is required", nameof(access));
        Raw = raw?.Clone();
    }

    /// <summary>The document types (they include <c>AccessRequest</c> or <c>AccessGrant</c>).</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The storage the document is scoped to.</summary>
    public Uri Storage { get; }

    /// <summary>Where notifications about the document are delivered.</summary>
    public Uri? Inbox { get; }

    /// <summary>The requested or granted access.</summary>
    public IReadOnlyList<AccessPolicy> Access { get; }

    /// <summary>The JSON document when it was parsed from a server, else null.</summary>
    public JsonElement? Raw { get; }

    /// <summary>The <c>application/lws+json</c> serialization.</summary>
    /// <returns>The document.</returns>
    public JsonObject ToJson()
    {
        var o = new JsonObject
        {
            ["@context"] = new JsonArray(Lws.Context),
            ["type"] = LwsJson.StringArray(Types),
        };
        if (Inbox is not null) o["inbox"] = Uris.ToText(Inbox);
        o["storage"] = Uris.ToText(Storage);
        var a = new JsonArray();
        foreach (AccessPolicy p in Access) a.Add(p.ToJson());
        o["access"] = a;
        return o;
    }

    private protected static (IReadOnlyList<string> Types, Uri Storage, Uri? Inbox, List<AccessPolicy> Access) ParseParts(JsonElement json, string requiredType)
    {
        LwsJson.RequireObject(json, requiredType);
        IReadOnlyList<string> types = LwsJson.StringOrArray(LwsJson.Get(json, "type"));
        if (!Lws.HasType(types, requiredType)) throw new ProtocolException($"Document type [{string.Join(", ", types)}] does not include {requiredType}");
        string storageText = LwsJson.GetString(json, "storage") ?? throw new ProtocolException($"The {requiredType} has no storage");
        Uri storage = Uris.Resolve(null, storageText) ?? throw new ProtocolException($"The {requiredType} storage is not an absolute URL");
        Uri? inbox = LwsJson.GetString(json, "inbox") is { } i
            ? Uris.Resolve(null, i) ?? throw new ProtocolException($"The {requiredType} inbox is not an absolute URL")
            : null;
        var policies = new List<AccessPolicy>();
        switch (LwsJson.Get(json, "access"))
        {
            case { ValueKind: JsonValueKind.Array } a:
                foreach (JsonElement p in a.EnumerateArray()) policies.Add(AccessPolicy.Parse(p));
                break;
            case { ValueKind: JsonValueKind.Object } single:
                policies.Add(AccessPolicy.Parse(single));
                break;
        }
        if (policies.Count == 0) throw new ProtocolException($"The {requiredType} has no access");
        return (types, storage, inbox, policies);
    }
}

/// <summary>
/// A request by an agent for access to resources of a storage.
/// <code>
/// var request = new AccessRequest(storage.Id,
///     [new AccessPolicy([Lws.Actions.Read], agent, AccessTarget.StorageResources(projects),
///                       [Constraint.Purpose(new Uri("https://purpose.example/collaboration"))])],
///     inbox: new Uri("https://id.example/agent/inbox/"));
/// </code>
/// </summary>
public sealed record AccessRequest : AccessDocument
{
    /// <summary>Creates an access request.</summary>
    /// <param name="storage">The storage.</param>
    /// <param name="access">The requested access (at least one policy).</param>
    /// <param name="inbox">Where to notify the requester.</param>
    public AccessRequest(Uri storage, IEnumerable<AccessPolicy> access, Uri? inbox = null)
        : base([Lws.Types.AccessRequest], storage, inbox, access, null)
    {
    }

    private AccessRequest(IEnumerable<string> types, Uri storage, Uri? inbox, IEnumerable<AccessPolicy> access, JsonElement raw)
        : base(types, storage, inbox, access, raw)
    {
    }

    /// <summary>Parses an access request document.</summary>
    /// <param name="json">The document.</param>
    /// <returns>The request.</returns>
    /// <exception cref="ProtocolException">It is not a valid access request.</exception>
    public static AccessRequest Parse(JsonElement json)
    {
        var p = ParseParts(json, Lws.Types.AccessRequest);
        return new AccessRequest(p.Types, p.Storage, p.Inbox, p.Access, json);
    }
}

/// <summary>
/// A record, created by a storage controller, of access granted to an agent. Creating or revoking (deleting) a grant
/// makes the server adjust its access policies.
/// </summary>
public sealed record AccessGrant : AccessDocument
{
    /// <summary>Creates an access grant.</summary>
    /// <param name="storage">The storage.</param>
    /// <param name="access">The granted access (at least one policy).</param>
    /// <param name="inbox">Where to notify about the grant.</param>
    public AccessGrant(Uri storage, IEnumerable<AccessPolicy> access, Uri? inbox = null)
        : base([Lws.Types.AccessGrant], storage, inbox, access, null)
    {
    }

    private AccessGrant(IEnumerable<string> types, Uri storage, Uri? inbox, IEnumerable<AccessPolicy> access, JsonElement raw)
        : base(types, storage, inbox, access, raw)
    {
    }

    /// <summary>A grant mirroring an access request (same storage, inbox and policies).</summary>
    /// <param name="request">The request.</param>
    /// <returns>The grant.</returns>
    public static AccessGrant Approving(AccessRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new AccessGrant(request.Storage, request.Access, request.Inbox);
    }

    /// <summary>Parses an access grant document.</summary>
    /// <param name="json">The document.</param>
    /// <returns>The grant.</returns>
    /// <exception cref="ProtocolException">It is not a valid access grant.</exception>
    public static AccessGrant Parse(JsonElement json)
    {
        var p = ParseParts(json, Lws.Types.AccessGrant);
        return new AccessGrant(p.Types, p.Storage, p.Inbox, p.Access, json);
    }
}
