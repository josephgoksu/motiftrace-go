# motiftrace-go

The Go SDK for [Motif](https://motiftrace.com): which channel brought the people who paid.

```sh
go get github.com/josephgoksu/motiftrace-go@latest
```

```go
import motif "github.com/josephgoksu/motiftrace-go"

// Reads MOTIF_INGEST_KEY and MOTIF_WEBSITE_ID. Strict fails at boot when they are missing.
mc, err := motif.NewClient(motif.Config{Strict: isProd})
if err != nil {
	return err
}
defer mc.Close(context.Background())

// In auth middleware, on every request where the user is known:
mc.Signup(motif.Signup{UserID: user.ID, CreatedAt: user.CreatedAt, Declined: user.AnalyticsConsent == "denied", OptedOut: user.IsStaff})
```

`Signup` returns at once and never blocks or fails a request. The first call
for a user sends `signup_completed` in the background; later calls cost
nothing. Failed sends retry on a later request, so a missed branch, late
consent or a restart heals by itself. `Declined` users (they said no to
analytics) are sent only as a count: no user id, just that a signup happened
that day, with a retry token Motif cannot reverse and deletes after 48 hours.
`OptedOut` users (staff, test accounts) are never sent.

Also: `mc.Milestone(ctx, motif.Milestone{...})` for other milestones,
`mc.Backfill(ctx, users)` to send past signups once, `mc.Stats()`,
`mc.Flush(ctx)` and `Config.OnResult` for health. No dependencies.

The browser side is the [`motiftrace`](https://www.npmjs.com/package/motiftrace)
npm package. Full guide: the [motiftrace README](https://www.npmjs.com/package/motiftrace).

This repository is a mirror of `sdk/go` in the Motif repository, published
for each release. MIT licensed.
