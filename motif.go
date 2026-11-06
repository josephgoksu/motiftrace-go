// Package motif sends server milestones to Motif from a Go backend.
//
// One call covers signups. Put it where every signed-in request passes (auth
// middleware, a /me handler), behind your own consent check if you have one:
//
//	mc, err := motif.NewClient(motif.Config{}) // MOTIF_INGEST_KEY, MOTIF_WEBSITE_ID
//	if err != nil { return err }              // only with Config.Strict
//	defer mc.Close(context.Background())
//	...
//	mc.Signup(motif.Signup{UserID: user.ID, CreatedAt: user.CreatedAt})
//
// Signup never blocks and never fails the request. It sends signup_completed
// once, in the background, for accounts younger than SignupWindow, and then
// remembers the user, so a steady request costs no call to Motif. A late
// consent, a missed auth branch, a failed send or a restart heal on the next
// request. Motif dedupes on (website, user, event, dedupe key), so a repeat
// returns Duplicate and changes nothing.
//
// Milestone sends any other milestone and waits for Motif's answer.
//
// Backfill repairs history once: it sends each past signup dated CreatedAt
// and returns what happened to every user.
//
// The module has no dependencies outside the standard library.
package motif

import (
	"bytes"
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// DefaultBaseURL is Motif's hosted API.
const DefaultBaseURL = "https://api.motiftrace.com/api"

// Status is what Motif did with a milestone.
type Status string

const (
	// Attached: counted on the user's identified visit.
	Attached Status = "attached"
	// Pending: held until the browser identifies this user, then counted.
	Pending Status = "pending"
	// Duplicate: already received; nothing changed.
	Duplicate Status = "duplicate"
	// Counted: a declined signup, counted with no person behind it.
	Counted Status = "counted"
)

// Milestone is one event for one of your users.
type Milestone struct {
	// WebsiteID defaults to Config.WebsiteID.
	WebsiteID string
	// UserID is the id your browser code passes to identify. Not an email.
	UserID string
	// EventName: a-z, 0-9, _ and -, up to 64 characters.
	EventName string
	// OccurredAt defaults to now; at most 90 days back.
	OccurredAt time.Time
	// DedupeKey: empty for one-time milestones; a stable id (an invoice id)
	// for one that repeats.
	DedupeKey string
}

// Signup is one signed-in user, as your app knows them.
type Signup struct {
	UserID string
	// CreatedAt is when your app created the account. It decides eligibility
	// only: an account older than Config.SignupWindow is skipped.
	CreatedAt time.Time
	// OccurredAt is optional. The signup is recorded at send time otherwise,
	// which keeps it after the visitor's first touch when consent came late.
	OccurredAt time.Time
	// WebsiteID defaults to Config.WebsiteID.
	WebsiteID string
	// OptedOut is true when the user explicitly opted out of analytics (they
	// declined, or your app records Global Privacy Control as a decline).
	// Nothing is sent; Stats().Skipped[OptedOut] counts it. Undecided users
	// are not opted out: a server signup stores nothing on their device.
	// OptedOut wins over Declined: use it for staff and test accounts too.
	OptedOut bool
	// Declined is true when the user declined analytics and you still want
	// the signup counted. The user id never leaves your server: Motif gets
	// only that a signup happened at CreatedAt, plus a retry token
	// (HMAC-SHA256 of the user id under your ingest key) that it clears after
	// 48 hours. Sent only within 24 hours of CreatedAt, so a signup counts on
	// its day; the Overview estimates its channel from your tracked signups.
	Declined bool
}

// Decision is what Signup did, synchronously.
type Decision string

const (
	Queued   Decision = "queued"    // will be sent in the background
	Known    Decision = "known"     // already acknowledged by Motif, or already queued
	Backoff  Decision = "backoff"   // a recent send failed; tried again after a pause
	OptedOut Decision = "opted_out" // the user opted out of analytics; nothing is sent
	TooOld   Decision = "too_old"   // CreatedAt is older than SignupWindow
	Invalid  Decision = "invalid"   // empty UserID, zero CreatedAt, or no website id
	Disabled Decision = "disabled"  // no key, a key Motif refused, or Close was called
	Dropped  Decision = "dropped"   // the queue is full; a later call tries again
)

// Failure reasons, as Result.Reason and Stats.Failed keys.
const (
	ReasonConfig      = "config"       // 401, 403, 404 or a missing key: fix configuration
	ReasonInvalid     = "invalid"      // another 4xx: the request itself is wrong
	ReasonConflict    = "conflict"     // 409: too many milestones wait for a user who never identified
	ReasonRateLimited = "rate_limited" // 429 after waiting for Retry-After
	ReasonServer      = "server"       // 5xx after retries
	ReasonNetwork     = "network"      // no answer after retries
	ReasonTimeout     = "timeout"      // Config.Deadline ran out
)

// Result is one finished send, background or awaited.
type Result struct {
	Kind      string // "signup", "declined", "milestone" or "backfill"
	WebsiteID string
	UserID    string
	EventName string
	// Outcome is "attached", "pending", "counted" (a declined signup),
	// "duplicate", "failed" or "dropped".
	Outcome string
	Reason  string // set when Outcome is "failed"
	Err     error
}

// Stats is a snapshot of what this process sent.
type Stats struct {
	Queued                       int
	Attached, Pending, Duplicate int64
	Counted                      int64 // declined signups counted
	Dropped                      int64
	Failed                       map[string]int64 // by Reason*
	Skipped                      map[Decision]int64
}

// Error is a send Motif refused or that never got an answer. StatusCode is 0
// for CONFIG, NETWORK and TIMEOUT.
type Error struct {
	StatusCode int
	Code       string
	Message    string
	Err        error
	retryAfter time.Duration
}

func (e *Error) Error() string {
	return fmt.Sprintf("motif: %d %s: %s", e.StatusCode, e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// Reason classifies the error as one of the Reason* constants.
func (e *Error) Reason() string {
	switch {
	case e.Code == "CONFIG" || e.StatusCode == 401 || e.StatusCode == 403 || e.StatusCode == 404:
		return ReasonConfig
	case e.StatusCode == http.StatusConflict:
		return ReasonConflict
	case e.StatusCode == 429:
		return ReasonRateLimited
	case e.StatusCode >= 500:
		return ReasonServer
	case e.Code == "TIMEOUT":
		return ReasonTimeout
	case e.StatusCode == 0:
		return ReasonNetwork
	}
	return ReasonInvalid
}

// Config sets up a Client. Every field is optional.
type Config struct {
	// APIKey is an ingest key (mtk_live_… or mtk_test_…). Defaults to $MOTIF_INGEST_KEY.
	APIKey string
	// WebsiteID defaults to $MOTIF_WEBSITE_ID. Signup needs one.
	WebsiteID string
	// Strict makes NewClient return an error for a missing or malformed key
	// or website id. Without it the problem is logged once, sends are off,
	// and the app still boots. Turn it on in production.
	Strict  bool
	BaseURL string
	HTTP    *http.Client
	// Timeout is per attempt. Default 5s.
	Timeout time.Duration
	// Deadline caps one send, retries and waits included. Default 10s.
	Deadline time.Duration
	// Retries after a network error, 429 or 5xx. 0 means the default (2);
	// negative means none.
	Retries int
	// SignupWindow: Signup skips accounts created longer ago. Default 30
	// days, at most 90 (Motif's backfill limit).
	SignupWindow time.Duration
	// BackfillRate is Backfill's sends per second. Default 10, at most 20
	// (Motif's limit per account, which live Signup sends share).
	BackfillRate int
	// QueueSize bounds the background queue. Default 1000.
	QueueSize int
	// CacheSize users are remembered as acknowledged for CacheTTL. Defaults 10000 and 24h.
	CacheSize int
	CacheTTL  time.Duration
	// OnResult is called once per finished send, from the sending goroutine.
	OnResult func(Result)
	// Logger receives config errors and the first failure of each kind.
	// Defaults to slog.Default().
	Logger *slog.Logger
}

const (
	signupEvent    = "signup_completed"
	milestonesPath = "/v1/milestones"
	declinedPath   = "/v1/milestones/declined"
	// declinedSuffix turns a user's signup key into their declined count's key.
	declinedSuffix = "\x00declined"
	// declinedWindow is how long after CreatedAt a declined signup is sent.
	// Motif keeps its retry token 48 hours, so a later resend could count twice.
	declinedWindow  = 24 * time.Hour
	failureBackoff  = time.Minute
	maxSignupWindow = 90 * 24 * time.Hour
	// BackfillWindow is how far back Motif accepts an occurred_at
	// (apps/api domain/milestones.go milestonePastMax).
	BackfillWindow = 90 * 24 * time.Hour
	// An hour short of Motif's limit, so a client clock that runs a little
	// slow is reported as TooOld here instead of as a 400 from Motif.
	backfillMargin = time.Hour
	// Motif stores up to 5 minutes ahead as now (clock skew) and refuses later.
	futureSkew = 5 * time.Minute
)

var (
	uuidRe = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyRe  = regexp.MustCompile(`^mtk_(live|test)_\S+$`)
)

type job struct {
	kind, key, path         string
	websiteID, userID, name string
	body                    []byte
	// done receives the finished send when someone waits for it (Backfill).
	done chan Result
}

type entry struct {
	key   string
	until time.Time
	ok    bool
}

// Client sends milestones. Build it with NewClient or New; it is safe for
// concurrent use.
type Client struct {
	apiKey string
	// BaseURL, HTTP and Retries may be changed before the first send.
	BaseURL string
	HTTP    *http.Client
	// Retries after a network error, 429 or 5xx; negative means none.
	Retries int

	websiteID string
	timeout   time.Duration
	deadline  time.Duration
	window    time.Duration
	rate      int
	queueSize int
	cacheSize int
	cacheTTL  time.Duration
	onResult  func(Result)
	log       *slog.Logger

	mu        sync.Mutex
	queue     []job
	inQueue   map[string]bool
	running   bool
	waiters   []chan struct{}
	lru       *list.List
	cache     map[string]*list.Element
	disabled  string
	deadSites map[string]bool
	closed    bool
	said      map[string]bool
	stats     Stats
}

// New returns a client for an ingest key with default settings. The website
// id comes from $MOTIF_WEBSITE_ID or each call.
func New(apiKey string) *Client {
	c, _ := NewClient(Config{APIKey: apiKey})
	if trimSpace(apiKey) == "" {
		// New was always given its key; do not fall back to the environment.
		c.apiKey, c.disabled = "", "no key"
	}
	return c
}

// NewClient builds a client from cfg. It returns an error only when
// cfg.Strict is set and the configuration is missing or malformed; otherwise
// it logs the problem once and returns a client whose sends are off.
func NewClient(cfg Config) (*Client, error) {
	key := trimSpace(cfg.APIKey)
	if key == "" {
		key = trimSpace(os.Getenv("MOTIF_INGEST_KEY"))
	}
	site := trimSpace(cfg.WebsiteID)
	if site == "" {
		site = trimSpace(os.Getenv("MOTIF_WEBSITE_ID"))
	}
	c := &Client{
		apiKey:    key,
		BaseURL:   orString(cfg.BaseURL, DefaultBaseURL),
		HTTP:      cfg.HTTP,
		Retries:   min(cfg.Retries, 10),
		websiteID: site,
		timeout:   orDuration(cfg.Timeout, 5*time.Second),
		deadline:  orDuration(cfg.Deadline, 10*time.Second),
		window:    min(orDuration(cfg.SignupWindow, 30*24*time.Hour), maxSignupWindow),
		rate:      min(orInt(cfg.BackfillRate, 10), 20),
		queueSize: orInt(cfg.QueueSize, 1000),
		cacheSize: orInt(cfg.CacheSize, 10000),
		cacheTTL:  orDuration(cfg.CacheTTL, 24*time.Hour),
		onResult:  cfg.OnResult,
		log:       cfg.Logger,
		inQueue:   map[string]bool{},
		lru:       list.New(),
		cache:     map[string]*list.Element{},
		deadSites: map[string]bool{},
		said:      map[string]bool{},
		stats:     Stats{Failed: map[string]int64{}, Skipped: map[Decision]int64{}},
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{}
	}
	if cfg.Retries == 0 {
		c.Retries = 2
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	var problems []string
	switch {
	case key == "":
		problems = append(problems, "MOTIF_INGEST_KEY is not set, so server milestones are off; create an ingest key in the website's setup in Motif")
		c.disabled = "no key"
	case !keyRe.MatchString(key):
		problems = append(problems, "the ingest key does not look like mtk_live_… or mtk_test_…; copy it again from Motif")
	}
	if site != "" && !uuidRe.MatchString(site) {
		problems = append(problems, fmt.Sprintf("website id %q is not a UUID; copy it from the website's setup in Motif", site))
	}
	if cfg.Strict && site == "" {
		problems = append(problems, "MOTIF_WEBSITE_ID is not set")
	}
	if cfg.Strict && len(problems) > 0 {
		return nil, &Error{Code: "CONFIG", Message: strings.Join(problems, "; ")}
	}
	for i, p := range problems {
		c.once(slog.LevelError, "config:"+strconv.Itoa(i), "motif: "+p)
	}
	return c, nil
}

// Signup records that this user signed up. Call it for every signed-in
// request. It never blocks and never returns an error; Decision says what it
// did, and OnResult and Stats report the send.
func (c *Client) Signup(s Signup) Decision {
	c.mu.Lock()
	d, j := c.signupLocked(s, time.Now())
	if d != Queued {
		c.stats.Skipped[d]++
		c.mu.Unlock()
		return d
	}
	// Queued under the lock that checked inQueue, so two concurrent requests
	// for one user cannot both send it.
	ok := c.enqueueLocked(j)
	c.mu.Unlock()
	if !ok {
		c.report(Result{Kind: j.kind, WebsiteID: j.websiteID, UserID: j.userID, EventName: j.name, Outcome: "dropped"})
		return Dropped
	}
	return Queued
}

func (c *Client) signupLocked(s Signup, now time.Time) (Decision, job) {
	if s.OptedOut {
		return OptedOut, job{}
	}
	if c.closed || c.disabled != "" {
		return Disabled, job{}
	}
	site := orString(trimSpace(s.WebsiteID), c.websiteID)
	user := trimSpace(s.UserID)
	if site == "" || user == "" || s.CreatedAt.IsZero() {
		c.onceLocked(slog.LevelError, "signup:invalid", "motif: Signup needs a UserID, a CreatedAt, and a website id (Config.WebsiteID or MOTIF_WEBSITE_ID)")
		return Invalid, job{}
	}
	if c.deadSites[site] {
		return Disabled, job{}
	}
	if now.Sub(s.CreatedAt) > c.window {
		return TooOld, job{}
	}
	key := site + "\x00" + user + "\x00" + signupEvent
	if s.Declined {
		return c.declinedLocked(s, site, user, key, now)
	}
	// Counted already as declined (they accepted after declining): not again.
	if c.countedLocked(key + declinedSuffix) {
		return Known, job{}
	}
	if d := c.seenLocked(key, now); d != "" {
		return d, job{}
	}
	body, _ := json.Marshal(request{WebsiteID: site, UserID: user, EventName: signupEvent, OccurredAt: utcOrNil(s.OccurredAt)})
	return Queued, job{kind: "signup", key: key, path: milestonesPath, websiteID: site, userID: user, name: signupEvent, body: body}
}

// declinedLocked queues the anonymous count for a user who declined. A user
// this process already queued or sent with their id (they declined after
// signing up) is not counted again.
func (c *Client) declinedLocked(s Signup, site, user, signupKey string, now time.Time) (Decision, job) {
	if now.Sub(s.CreatedAt) > declinedWindow {
		return TooOld, job{}
	}
	if c.countedLocked(signupKey) {
		return Known, job{}
	}
	key := signupKey + declinedSuffix
	if d := c.seenLocked(key, now); d != "" {
		return d, job{}
	}
	// A CreatedAt ahead of this clock would be refused past Motif's skew
	// allowance; an event never lands in the future.
	at := s.CreatedAt
	if at.After(now) {
		at = now
	}
	at = at.UTC()
	body, _ := json.Marshal(declinedRequest{WebsiteID: site, Token: declinedToken(c.apiKey, site, user), OccurredAt: &at})
	return Queued, job{kind: "declined", key: key, path: declinedPath, websiteID: site, userID: user, name: signupEvent, body: body}
}

// countedLocked reports whether key is queued or acknowledged, so the same
// user's signup in the other form (with their id, or declined) is not counted
// a second time.
func (c *Client) countedLocked(key string) bool {
	if c.inQueue[key] {
		return true
	}
	el, ok := c.cache[key]
	return ok && el.Value.(*entry).ok
}

// seenLocked answers Known or Backoff for a key that is queued or remembered,
// and "" when it should be sent.
func (c *Client) seenLocked(key string, now time.Time) Decision {
	if c.inQueue[key] {
		return Known
	}
	if el, ok := c.cache[key]; ok {
		e := el.Value.(*entry)
		if now.Before(e.until) {
			c.lru.MoveToFront(el)
			if e.ok {
				return Known
			}
			return Backoff
		}
		c.lru.Remove(el)
		delete(c.cache, key)
	}
	return ""
}

// Milestone sends m and waits for Motif's answer, at most Config.Deadline.
// Never fail a user's request over it: log the error.
func (c *Client) Milestone(ctx context.Context, m Milestone) (Status, error) {
	site := orString(trimSpace(m.WebsiteID), c.websiteID)
	user := trimSpace(m.UserID)
	event := trimSpace(m.EventName)
	dedupe := trimSpace(m.DedupeKey)
	c.mu.Lock()
	off := c.disabled
	switch {
	case off == "" && c.closed:
		off = "closed"
	case off == "" && site != "" && c.deadSites[site]:
		off = "unknown website"
	}
	c.mu.Unlock()
	if off != "" {
		return "", &Error{Code: "CONFIG", Message: "sends are off (" + off + ")"}
	}
	if site == "" || user == "" || event == "" {
		return "", &Error{Code: "INVALID", Message: "Milestone needs a WebsiteID, UserID, and EventName"}
	}
	body, err := json.Marshal(request{WebsiteID: site, UserID: user, EventName: event, OccurredAt: utcOrNil(m.OccurredAt), DedupeKey: dedupe})
	if err != nil {
		return "", err
	}
	res := Result{Kind: "milestone", WebsiteID: site, UserID: user, EventName: event}
	status, err := c.post(ctx, milestonesPath, body)
	if err != nil {
		var me *Error
		if errors.As(err, &me) && me.Code != "CONFIG" {
			res.Outcome, res.Reason, res.Err = "failed", c.noteFailure(me, site), err
			c.report(res)
		}
		return "", err
	}
	res.Outcome = string(status)
	c.report(res)
	return status, nil
}

// BackfillSent counts the users Motif accepted.
type BackfillSent struct {
	Attached int `json:"attached"`
	Pending  int `json:"pending"`
	// Counted: declined users, sent as a count with no user id.
	Counted int `json:"counted,omitempty"`
}

// BackfillReport is what Backfill did. Every user lands in exactly one
// bucket: Sent, Duplicate, TooOld, Invalid, OptedOut or one Failed reason.
// Declined users are sent as counts (Sent.Counted).
type BackfillReport struct {
	Total int `json:"total"`
	// Eligible users were valid, inside the window, and not repeated in the input.
	Eligible int          `json:"eligible"`
	Sent     BackfillSent `json:"sent"`
	// Duplicate: Motif already had the server signup (from Signup or an
	// earlier backfill), or the input repeats the user.
	Duplicate int `json:"duplicate"`
	// TooOld: created longer ago than BackfillWindow.
	TooOld int `json:"too_old"`
	// Invalid: empty UserID, zero CreatedAt, a CreatedAt in the future, or no website id.
	Invalid int `json:"invalid"`
	// OptedOut: users with OptedOut set to true (never sent).
	OptedOut int            `json:"opted_out,omitempty"`
	Failed   map[string]int `json:"failed"`
}

// Backfill repairs history: it sends signup_completed for each past account,
// dated CreatedAt (OccurredAt is ignored), and returns what happened to every
// user. Unlike Signup, which records at send time so a late send lands after
// the visitor's first touch, a backfill wants the real day: a month of past
// signups sent today would otherwise pile into today's count.
//
// Sends go one at a time through the shared queue (with live Signup sends),
// paced to Config.BackfillRate, with the same retries and Retry-After waits.
// It is idempotent with Signup and with itself: Motif keeps one
// signup_completed per user, so a repeat counts as Duplicate. The error is
// non-nil only when ctx ends first; the report then covers the users so far,
// and a send already queued still finishes.
func (c *Client) Backfill(ctx context.Context, users []Signup) (BackfillReport, error) {
	out := BackfillReport{Total: len(users), Failed: map[string]int{}}
	gap := time.Second / time.Duration(max(c.rate, 1))
	seen := map[string]bool{}
	var next time.Time
	for _, u := range users {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if u.OptedOut {
			c.mu.Lock()
			c.stats.Skipped[OptedOut]++
			c.mu.Unlock()
			out.OptedOut++
			continue
		}
		site := orString(trimSpace(u.WebsiteID), c.websiteID)
		user := trimSpace(u.UserID)
		now := time.Now()
		key := site + "\x00" + user + "\x00" + signupEvent
		switch {
		case site == "" || user == "" || u.CreatedAt.IsZero() || u.CreatedAt.Sub(now) > futureSkew:
			out.Invalid++
			continue
		case now.Sub(u.CreatedAt) > BackfillWindow-backfillMargin:
			out.TooOld++
			continue
		case seen[key]:
			out.Duplicate++
			continue
		}
		seen[key] = true
		out.Eligible++
		res, err := c.sendBackfill(ctx, backfillJob(c.apiKey, key, site, user, u), time.Until(next))
		if err != nil {
			return out, err
		}
		next = time.Now().Add(gap)
		switch res.Outcome {
		case string(Attached):
			out.Sent.Attached++
		case string(Pending):
			out.Sent.Pending++
		case string(Counted):
			out.Sent.Counted++
		case string(Duplicate):
			out.Duplicate++
		default:
			out.Failed[orString(res.Reason, ReasonNetwork)]++
		}
	}
	return out, nil
}

// backfillJob is the send for one past signup, dated CreatedAt: with the
// user id, or for a declined user only the count (see Signup.Declined).
// Motif drops a repeated declined count for 48 hours only, so re-running a
// backfill of declined users later counts them again.
func backfillJob(apiKey, key, site, user string, u Signup) job {
	if u.Declined {
		at := u.CreatedAt.UTC()
		body, _ := json.Marshal(declinedRequest{WebsiteID: site, Token: declinedToken(apiKey, site, user), OccurredAt: &at})
		return job{kind: "backfill", key: key + declinedSuffix, path: declinedPath, websiteID: site, userID: user, name: signupEvent, body: body, done: make(chan Result, 1)}
	}
	body, _ := json.Marshal(request{WebsiteID: site, UserID: user, EventName: signupEvent, OccurredAt: utcOrNil(u.CreatedAt)})
	return job{kind: "backfill", key: key, path: milestonesPath, websiteID: site, userID: user, name: signupEvent, body: body, done: make(chan Result, 1)}
}

// declinedToken is the retry token for a declined signup: HMAC-SHA256 of the
// user id under the ingest key, which Motif stores only as a hash, so Motif
// cannot recompute or reverse it.
func declinedToken(apiKey, site, user string) string {
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte(site + "\x00" + user))
	return hex.EncodeToString(mac.Sum(nil))
}

// sendBackfill puts one backfill send on the shared queue and waits for it.
// A user this process already got acknowledged is a duplicate with no
// request, and one whose sends are off fails at once: neither waits out the
// pace, so a refused key ends the run instead of pacing through every user.
func (c *Client) sendBackfill(ctx context.Context, j job, wait time.Duration) (Result, error) {
	key, site, user := j.key, j.websiteID, j.userID
	paced := wait <= 0
	for {
		c.mu.Lock()
		off := c.disabled
		switch {
		case off == "" && c.closed:
			off = "closed"
		case off == "" && c.deadSites[site]:
			off = "unknown website"
		}
		if off != "" {
			c.mu.Unlock()
			// Reported like a queued send the refusal caught, so OnResult and
			// Stats see every failed user.
			res := Result{Kind: j.kind, WebsiteID: site, UserID: user, EventName: signupEvent, Outcome: "failed", Reason: ReasonConfig,
				Err: &Error{Code: "CONFIG", Message: "sends are off (" + off + ")"}}
			c.report(res)
			return res, nil
		}
		if el, ok := c.cache[key]; ok {
			if e := el.Value.(*entry); e.ok && time.Now().Before(e.until) {
				c.mu.Unlock()
				return Result{Outcome: string(Duplicate)}, nil
			}
		}
		// Wait for room rather than drop: live Signup sends keep their place.
		if paced && len(c.queue) < c.queueSize {
			c.enqueueLocked(j)
			c.mu.Unlock()
			break
		}
		c.mu.Unlock()
		pause := 100 * time.Millisecond
		if !paced {
			pause, paced = wait, true
		}
		if err := sleepCtx(ctx, pause); err != nil {
			return Result{}, err
		}
	}
	select {
	case res := <-j.done:
		return res, nil
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Flush waits until the background queue is empty or ctx is done. For a
// serverless handler, run it before the function returns.
func (c *Client) Flush(ctx context.Context) error {
	c.mu.Lock()
	if !c.running && len(c.queue) == 0 {
		c.mu.Unlock()
		return nil
	}
	w := make(chan struct{})
	c.waiters = append(c.waiters, w)
	c.mu.Unlock()
	select {
	case <-w:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops new background sends and waits for queued ones, at most until
// ctx is done. Call it on shutdown.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Flush(ctx)
}

// Stats returns a snapshot, for a metric or a health check.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Queued = len(c.queue)
	s.Failed = make(map[string]int64, len(c.stats.Failed))
	for k, v := range c.stats.Failed {
		s.Failed[k] = v
	}
	s.Skipped = make(map[Decision]int64, len(c.stats.Skipped))
	for k, v := range c.stats.Skipped {
		s.Skipped[k] = v
	}
	return s
}

// ---- background queue ------------------------------------------------------

// enqueueLocked puts a job on the one shared queue; c.mu is held. A new kind
// of background send is a new job, not a new queue. False when the queue is
// full: the caller reports the drop once it has unlocked.
func (c *Client) enqueueLocked(j job) bool {
	if len(c.queue) >= c.queueSize {
		c.onceLocked(slog.LevelWarn, "dropped", fmt.Sprintf("motif: the send queue is full (%d); dropped sends are retried on a later call", c.queueSize))
		return false
	}
	c.queue = append(c.queue, j)
	c.inQueue[j.key] = true
	if !c.running {
		c.running = true
		go c.pump()
	}
	return true
}

// pump sends one job at a time, so a backlog after a deploy stays under the
// API's rate limit.
func (c *Client) pump() {
	for {
		c.mu.Lock()
		if len(c.queue) == 0 {
			c.running = false
			ws := c.waiters
			c.waiters = nil
			c.mu.Unlock()
			for _, w := range ws {
				close(w)
			}
			return
		}
		j := c.queue[0]
		c.queue = c.queue[1:]
		off := c.disabled
		if off == "" && c.deadSites[j.websiteID] {
			off = "unknown website"
		}
		c.mu.Unlock()
		c.run(j, off)
		c.mu.Lock()
		delete(c.inQueue, j.key)
		c.mu.Unlock()
	}
}

func (c *Client) run(j job, off string) {
	res := c.send(j, off)
	c.report(res)
	if j.done != nil {
		j.done <- res
	}
}

func (c *Client) send(j job, off string) Result {
	res := Result{Kind: j.kind, WebsiteID: j.websiteID, UserID: j.userID, EventName: j.name}
	if off != "" {
		// Queued before Motif refused the key or the site: say so, do not send.
		res.Outcome, res.Reason, res.Err = "failed", ReasonConfig, &Error{Code: "CONFIG", Message: "sends are off (" + off + ")"}
		return res
	}
	status, err := c.post(context.Background(), j.path, j.body)
	if err != nil {
		var me *Error
		if !errors.As(err, &me) {
			me = &Error{Code: "NETWORK", Message: err.Error(), Err: err}
		}
		reason := c.noteFailure(me, j.websiteID)
		// A request Motif refused as wrong fails the same way every time:
		// wait as long as a success is remembered instead of resending each minute.
		pause := failureBackoff
		if reason == ReasonInvalid || reason == ReasonConflict {
			pause = c.cacheTTL
		}
		c.remember(j.key, false, pause)
		res.Outcome, res.Reason, res.Err = "failed", reason, err
		return res
	}
	c.remember(j.key, true, c.cacheTTL)
	res.Outcome = string(status)
	return res
}

func (c *Client) remember(key string, ok bool, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, found := c.cache[key]; found {
		c.lru.Remove(el)
	}
	c.cache[key] = c.lru.PushFront(&entry{key: key, until: time.Now().Add(ttl), ok: ok})
	for c.lru.Len() > c.cacheSize {
		last := c.lru.Back()
		c.lru.Remove(last)
		delete(c.cache, last.Value.(*entry).key)
	}
}

func (c *Client) report(r Result) {
	c.mu.Lock()
	switch r.Outcome {
	case string(Attached):
		c.stats.Attached++
	case string(Pending):
		c.stats.Pending++
	case string(Duplicate):
		c.stats.Duplicate++
	case string(Counted):
		c.stats.Counted++
	case "dropped":
		c.stats.Dropped++
	case "failed":
		c.stats.Failed[r.Reason]++
	}
	c.mu.Unlock()
	if c.onResult != nil {
		func() {
			defer func() { _ = recover() }() // the hook is the app's; its panic is not ours
			c.onResult(r)
		}()
	}
}

// noteFailure classifies a failure: a refused key stops all sends, a 404
// stops its website id, and each kind is logged once.
func (c *Client) noteFailure(e *Error, site string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch e.StatusCode {
	case 401, 403:
		c.disabled = "HTTP " + strconv.Itoa(e.StatusCode)
		c.onceLocked(slog.LevelError, "http:"+strconv.Itoa(e.StatusCode), fmt.Sprintf("motif: Motif refused the ingest key (%d %s: %s); server milestones are off until the key is fixed and the app restarts", e.StatusCode, e.Code, e.Message))
	case 404:
		c.deadSites[site] = true
		c.onceLocked(slog.LevelError, "404:"+site, fmt.Sprintf("motif: Motif does not know website %s for this key (404); check MOTIF_WEBSITE_ID", site))
	default:
		c.onceLocked(slog.LevelWarn, "fail:"+e.Reason(), fmt.Sprintf("motif: a send failed (%s: %s); later %s failures are counted in Stats only", e.Reason(), e.Message, e.Reason()))
	}
	return e.Reason()
}

func (c *Client) once(level slog.Level, key, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onceLocked(level, key, msg)
}

func (c *Client) onceLocked(level slog.Level, key, msg string) {
	if c.said[key] {
		return
	}
	c.said[key] = true
	c.log.Log(context.Background(), level, msg)
}

// ---- transport ---------------------------------------------------------------

type request struct {
	WebsiteID  string     `json:"website_id"`
	UserID     string     `json:"user_id"`
	EventName  string     `json:"event_name"`
	OccurredAt *time.Time `json:"occurred_at,omitempty"`
	DedupeKey  string     `json:"dedupe_key,omitempty"`
}

type declinedRequest struct {
	WebsiteID  string     `json:"website_id"`
	Token      string     `json:"token"`
	OccurredAt *time.Time `json:"occurred_at,omitempty"`
}

type response struct {
	Status  Status `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// post sends one request with retries inside one deadline.
func (c *Client) post(ctx context.Context, path string, body []byte) (Status, error) {
	if c.apiKey == "" {
		return "", &Error{Code: "CONFIG", Message: "api key is required"}
	}
	ctx, cancel := context.WithTimeout(ctx, c.deadline)
	defer cancel()
	deadline, _ := ctx.Deadline()
	url := strings.TrimRight(c.BaseURL, "/") + path
	retries := min(max(c.Retries, 0), 10) // negative means no retries, never no attempt
	var last *Error
	for i := 0; i <= retries; i++ {
		if i > 0 {
			wait := time.Duration(250<<(i-1)) * time.Millisecond
			if last != nil && last.StatusCode == http.StatusTooManyRequests {
				wait = max(wait, last.retryAfter)
			}
			wait += time.Duration(rand.Int64N(int64(250 * time.Millisecond))) // #nosec G404 -- retry jitter, not security
			if time.Now().Add(wait).After(deadline) {
				return "", c.timeoutOr(last)
			}
			select {
			case <-ctx.Done():
				return "", c.timeoutOr(last)
			case <-time.After(wait):
			}
		}
		status, retry, err := c.attempt(ctx, url, body)
		if err == nil {
			return status, nil
		}
		last = err
		if ctx.Err() != nil {
			return "", c.timeoutOr(last)
		}
		if !retry {
			break
		}
	}
	return "", last
}

// timeoutOr keeps Motif's own answer (a 429 or 5xx) when there was one;
// otherwise the deadline is the reason.
func (c *Client) timeoutOr(last *Error) error {
	if last != nil && last.StatusCode != 0 {
		return last
	}
	e := &Error{Code: "TIMEOUT", Message: fmt.Sprintf("no answer within %s", c.deadline)}
	if last != nil {
		e.Err = last
	}
	return e
}

func (c *Client) attempt(ctx context.Context, url string, body []byte) (Status, bool, *Error) {
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", false, &Error{Code: "CONFIG", Message: err.Error(), Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", true, &Error{Code: "NETWORK", Message: err.Error(), Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		// The body was cut off mid-read. A 2xx means Motif already committed,
		// so this is a transport failure to retry (which answers Duplicate),
		// not an HTTP error.
		return "", true, &Error{Code: "NETWORK", Message: "response cut off: " + err.Error(), Err: err}
	}
	var out response
	_ = json.Unmarshal(raw, &out) // an error page is not JSON
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out.Status != "" {
		return out.Status, false, nil
	}
	e := &Error{StatusCode: resp.StatusCode, Code: orString(out.Code, "HTTP_ERROR"), Message: out.Message}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	return "", resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, e
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseFloat(v, 64); err == nil && secs > 0 {
		return time.Duration(secs * float64(time.Second))
	}
	if at, err := http.ParseTime(v); err == nil {
		return max(at.Sub(now), 0)
	}
	return 0
}

func utcOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func orString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func orDuration(v, fallback time.Duration) time.Duration {
	if v <= 0 {
		return fallback
	}
	return v
}

func orInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func trimSpace(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r == '\uFEFF' || unicode.IsSpace(r)
	})
}
