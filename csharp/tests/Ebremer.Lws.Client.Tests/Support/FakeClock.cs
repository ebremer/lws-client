// SPDX-License-Identifier: MIT
namespace Ebremer.Lws.Tests.Support;

/// <summary>A settable clock.</summary>
internal sealed class FakeClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}
