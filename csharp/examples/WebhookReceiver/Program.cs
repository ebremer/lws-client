// SPDX-License-Identifier: MIT
// Receives and verifies webhook notifications (RFC 9421 signatures) for changes in a storage root.
//
//   dotnet run --project examples/WebhookReceiver -- http://localhost:8787/root/ 9090
using System.Net;
using Ebremer.Lws;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Notifications;

var start = new Uri(args.Length > 0 ? args[0] : "http://localhost:8787/root/");
int port = args.Length > 1 ? int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 9090;

using var authenticator = new TokenExchangeAuthenticator(SelfSignedCredentials.DidKey(SigningKey.GenerateP256()));
using var client = new LwsClient(new LwsClientOptions { Authenticator = authenticator });
StorageDescription storage = await client.DiscoverStorageAsync(start);

// The verifier fetches the storage description to find the signing key the keyid names.
using var verifier = new WebhookVerifier(new WebhookVerifierOptions { Client = client, TrustedStorages = [storage.Id] });

var inbox = new Uri($"http://127.0.0.1:{port}/inbox");
using var listener = new HttpListener();
listener.Prefixes.Add($"http://127.0.0.1:{port}/");
listener.Start();

Subscription subscription = await client.SubscribeAsync(storage.NotificationService
    ?? throw new InvalidOperationException("The storage has no notification service"),
    new WebhookSubscriptionRequest(inbox, [storage.GetStorageRoot()]));
Console.WriteLine($"Subscribed: {subscription.Url}; change something in {storage.GetStorageRoot()} (Ctrl+C to stop)");

using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};
using (stop.Token.Register(listener.Stop))
{
    while (!stop.IsCancellationRequested)
    {
        HttpListenerContext context;
        try
        {
            context = await listener.GetContextAsync();
        }
        catch (HttpListenerException) when (stop.IsCancellationRequested)
        {
            break;
        }
        try
        {
            // The URL to verify against is the inbox as registered, not necessarily the one the request arrived at.
            VerifiedNotification v = await verifier.VerifyAsync(context.Request, inbox);
            foreach (Activity a in v.Notification.Activities)
            {
                Console.WriteLine($"{string.Join(",", a.Types)} {a.Object.Id} (signed by {v.KeyId})");
            }
            context.Response.StatusCode = 204;
        }
        catch (SignatureVerificationException e)
        {
            Console.Error.WriteLine($"Rejected delivery: {e.Message}");
            context.Response.StatusCode = 401;
        }
        context.Response.Close();
    }
}

await client.UnsubscribeAsync(subscription.Url);
Console.WriteLine("Unsubscribed");
