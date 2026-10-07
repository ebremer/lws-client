// SPDX-License-Identifier: MIT
global using static Ebremer.Lws.Tests.Support.TestToken;

namespace Ebremer.Lws.Tests.Support;

/// <summary>The current test's cancellation token, for every call that takes one.</summary>
internal static class TestToken
{
    public static CancellationToken Ct => TestContext.Current.CancellationToken;
}
