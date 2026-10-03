# Shared libraries

These modules hold behavior that several services need. Use them rather than
re-implementing their concerns, and fix recurring problems in the library
instead of in each service. Pin a tagged release.

| Module | Add it when the service | It owns | The service keeps |
| --- | --- | --- | --- |
| `go.michaelspost.com/mcpkit` | exposes MCP tools | SDK server construction, stdio shutdown, Streamable HTTP limits, localhost and cross-origin defaults, tool annotations, in-memory test connections | Tool schemas, authentication, authorization, confirmation, audit, persistence |
| `go.michaelspost.com/oidcrp` | has a browser UI for people | The OIDC relying-party flow | Session storage through `SessionManager`, user policy |
| `go.michaelspost.com/tintwire-go` | sends notifications | Tintwire card delivery with optional Mattermost failover | Message content and notification policy |
| `go.michaelspost.com/pwa-kit` | sends web push to a PWA | Permission, subscription, VAPID and notification-click handling | Subscription storage, recipients, TTL and urgency, worker caching |

## MCP tools with mcpkit

```go
server := mcpkit.MustServer(mcpkit.ServerConfig{
    Name:    "servicename",
    Version: version,
    Logger:  logger,
})

mcp.AddTool(server, &mcp.Tool{
    Name:        "servicename_status",
    Description: "Report current status.",
    Annotations: mcpkit.ReadOnly(false),
}, status)
```

Annotations are advisory. The server must still enforce read, write and
destructive permissions itself.

## Sign-in with oidcrp

```go
auth := oidcrp.New(oidcrp.Config{
    Issuer:          issuer,
    ClientID:        clientID,
    ClientSecret:    clientSecret,
    RedirectURL:     redirectURL,
    StateCookieName: "servicename_oidc",
    LoginPath:       "/login",
    SuccessPath:     "/",
    APIPrefixes:     []string{"/api/"},
}, sessions)

auth.Register(mux)
mux.HandleFunc("GET /", auth.Require(index))
```

## Notifications with tintwire-go

```go
client, err := tintwire.New(
    tintwireURL,
    os.Getenv("SERVICENAME_TINTWIRE_TOKEN"),
    tintwire.WithMattermostFailover(os.Getenv("SERVICENAME_MATTERMOST_WEBHOOK_URL")),
)
if err != nil {
    return err
}

_, err = client.Publish(ctx, tintwire.Card{
    Channel:  "#servicename",
    Title:    "Something needs attention",
    Severity: tintwire.SeverityWarning,
    Source:   "servicename",
})
```

Publish through Tintwire instead of posting to Mattermost directly.

## Web push with pwa-kit

Follow the pwa-kit `examples/minimal` integration and its README adoption
checklist. Serve the embedded scripts from the service:

```go
mux.Handle("GET /pwa-kit/", pwakit.Handler())
```
