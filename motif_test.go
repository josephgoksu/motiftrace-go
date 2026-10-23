package motif

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMilestoneSendsKeyAndBody(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/milestones" || r.Header.Get("Authorization") != "Bearer mtk_test_k" {
			t.Errorf("path %s auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()
	c := New("mtk_test_k")
	c.BaseURL = srv.URL + "/api/"
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s, err := c.Milestone(context.Background(), Milestone{WebsiteID: "w", UserID: "42", EventName: "signup_completed", OccurredAt: at})
	if err != nil || s != Pending {
		t.Fatalf("status %q err %v", s, err)
	}
	if got["user_id"] != "42" || got["occurred_at"] != "2026-10-01T00:00:00Z" || got["dedupe_key"] != nil {
		t.Fatalf("body %v", got)
	}
}

func TestMilestoneRetries5xxNot4xx(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"attached"}`))
	}))
	defer srv.Close()
	c := New("k")
	c.BaseURL = srv.URL
	if s, err := c.Milestone(context.Background(), Milestone{WebsiteID: "w", UserID: "u", EventName: "x"}); err != nil || s != Attached || calls != 2 {
		t.Fatalf("status %q err %v calls %d", s, err, calls)
	}

	calls = 0
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"FORBIDDEN","message":"this is a read key; milestones need an ingest key"}`))
	}))
	defer bad.Close()
	c.BaseURL = bad.URL
	_, err := c.Milestone(context.Background(), Milestone{WebsiteID: "w", UserID: "u", EventName: "x"})
	var me *Error
	if !errors.As(err, &me) || me.StatusCode != 403 || me.Code != "FORBIDDEN" || calls != 1 {
		t.Fatalf("err %v calls %d", err, calls)
	}
}

func TestNegativeRetriesStillSends(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"status":"duplicate"}`))
	}))
	defer srv.Close()
	c := New("k")
	c.BaseURL, c.Retries = srv.URL, -1
	if s, err := c.Milestone(context.Background(), Milestone{WebsiteID: "w", UserID: "u", EventName: "x"}); err != nil || s != Duplicate || calls != 1 {
		t.Fatalf("status %q err %v calls %d", s, err, calls)
	}
}

const site = "11111111-1111-4111-8111-111111111111"

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// server answers each POST with handler and records the bodies it saw.
type recorder struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (r *recorder) serve(t *testing.T, handler func(n int, w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(req.Body).Decode(&b)
		r.mu.Lock()
		r.bodies = append(r.bodies, b)
		n := len(r.bodies)
		r.mu.Unlock()
		handler(n, w)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func client(t *testing.T, url string, cfg Config) *Client {
	t.Helper()
	cfg.APIKey, cfg.WebsiteID, cfg.BaseURL = "mtk_test_k", site, url
	if cfg.Logger == nil {
		cfg.Logger = quiet()
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func flush(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSignupSendsOnceAtSendTimeAndThenCostsNothing(t *testing.T) {
	rec := &recorder{}
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) { _, _ = w.Write([]byte(`{"status":"pending"}`)) })
	var results []Result
	var rmu sync.Mutex
	c := client(t, srv.URL, Config{OnResult: func(r Result) { rmu.Lock(); results = append(results, r); rmu.Unlock() }})
	created := time.Now().Add(-48 * time.Hour)
	if d := c.Signup(Signup{UserID: "7", CreatedAt: created}); d != Queued {
		t.Fatalf("first %s", d)
	}
	if d := c.Signup(Signup{UserID: "7", CreatedAt: created}); d != Known {
		t.Fatalf("while queued %s", d)
	}
	flush(t, c)
	if d := c.Signup(Signup{UserID: " 7 ", CreatedAt: created}); d != Known {
		t.Fatalf("after ack %s", d)
	}
	if rec.count() != 1 {
		t.Fatalf("requests %d", rec.count())
	}
	b := rec.bodies[0]
	if b["event_name"] != "signup_completed" || b["user_id"] != "7" || b["website_id"] != site {
		t.Fatalf("body %v", b)
	}
	if _, ok := b["occurred_at"]; ok {
		t.Fatalf("occurred_at sent by default: %v", b)
	}
	if len(results) != 1 || results[0].Outcome != "pending" || c.Stats().Pending != 1 {
		t.Fatalf("results %+v stats %+v", results, c.Stats())
	}
}

// Concurrent requests for one user queue it once: the inQueue check and the
// enqueue happen under one lock.
func TestConcurrentSignupsForOneUserQueueOnce(t *testing.T) {
	rec := &recorder{}
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) { _, _ = w.Write([]byte(`{"status":"pending"}`)) })
	c := client(t, srv.URL, Config{})
	var queued atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Signup(Signup{UserID: "same", CreatedAt: time.Now()}) == Queued {
				queued.Add(1)
			}
		}()
	}
	wg.Wait()
	flush(t, c)
	if queued.Load() != 1 || rec.count() != 1 {
		t.Fatalf("queued %d, requests %d, want 1 and 1", queued.Load(), rec.count())
	}
}

func TestSignupEligibility(t *testing.T) {
	rec := &recorder{}
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) { _, _ = w.Write([]byte(`{"status":"attached"}`)) })
	c := client(t, srv.URL, Config{})
	if d := c.Signup(Signup{UserID: "old", CreatedAt: time.Now().Add(-31 * 24 * time.Hour)}); d != TooOld {
		t.Fatalf("old %s", d)
	}
	if d := c.Signup(Signup{UserID: "", CreatedAt: time.Now()}); d != Invalid {
		t.Fatalf("empty %s", d)
	}
	if d := c.Signup(Signup{UserID: "u"}); d != Invalid {
		t.Fatalf("zero createdAt %s", d)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if d := c.Signup(Signup{UserID: "u", CreatedAt: time.Now(), OccurredAt: at}); d != Queued {
		t.Fatalf("new %s", d)
	}
	flush(t, c)
	if rec.count() != 1 || rec.bodies[0]["occurred_at"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("bodies %v", rec.bodies)
	}
}

func TestMissingKeyBootsLogsOnceAndStrictFails(t *testing.T) {
	t.Setenv("MOTIF_INGEST_KEY", "")
	var logs bytes.Buffer
	c, err := NewClient(Config{WebsiteID: site, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Signup(Signup{UserID: "u", CreatedAt: time.Now()}); d != Disabled {
		t.Fatalf("decision %s", d)
	}
	c.Signup(Signup{UserID: "u", CreatedAt: time.Now()})
	if n := strings.Count(logs.String(), "MOTIF_INGEST_KEY"); n != 1 || !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("logs %q", logs.String())
	}
	if _, err := NewClient(Config{WebsiteID: site, Strict: true}); err == nil {
		t.Fatal("strict without key")
	}
	if _, err := NewClient(Config{APIKey: "mtk_live_x", WebsiteID: "site-1", Strict: true}); err == nil || !strings.Contains(err.Error(), "not a UUID") {
		t.Fatalf("strict bad site: %v", err)
	}
	t.Setenv("MOTIF_INGEST_KEY", "mtk_live_env")
	t.Setenv("MOTIF_WEBSITE_ID", site)
	if _, err := NewClient(Config{Strict: true}); err != nil {
		t.Fatalf("env config: %v", err)
	}
}

func TestRefusedKeyIsConfigNotRetriedAndTurnsSendsOff(t *testing.T) {
	rec := &recorder{}
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"UNAUTHORIZED","message":"unknown key"}`))
	})
	c := client(t, srv.URL, Config{})
	c.Signup(Signup{UserID: "a", CreatedAt: time.Now()})
	flush(t, c)
	if rec.count() != 1 || c.Stats().Failed[ReasonConfig] != 1 {
		t.Fatalf("requests %d stats %+v", rec.count(), c.Stats())
	}
	if d := c.Signup(Signup{UserID: "b", CreatedAt: time.Now()}); d != Disabled {
		t.Fatalf("after 401 %s", d)
	}
}

func TestConflictIsSurfacedNotRetried(t *testing.T) {
	rec := &recorder{}
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"CONFLICT","message":"too many waiting"}`))
	})
	c := client(t, srv.URL, Config{})
	c.Signup(Signup{UserID: "a", CreatedAt: time.Now()})
	flush(t, c)
	if rec.count() != 1 || c.Stats().Failed[ReasonConflict] != 1 {
		t.Fatalf("requests %d stats %+v", rec.count(), c.Stats())
	}
	if d := c.Signup(Signup{UserID: "b", CreatedAt: time.Now()}); d != Queued {
		t.Fatalf("a 409 is about one user, got %s", d)
	}
	flush(t, c)
}

func TestFailedSignupBacksOffThenRetries(t *testing.T) {
	rec := &recorder{}
	var fail atomic.Bool
	fail.Store(true)
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"attached"}`))
	})
	c := client(t, srv.URL, Config{Retries: -1})
	c.Signup(Signup{UserID: "u", CreatedAt: time.Now()})
	flush(t, c)
	if d := c.Signup(Signup{UserID: "u", CreatedAt: time.Now()}); d != Backoff {
		t.Fatalf("after failure %s", d)
	}
	// Age the failure past the pause.
	c.mu.Lock()
	for _, el := range c.cache {
		el.Value.(*entry).until = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	fail.Store(false)
	if d := c.Signup(Signup{UserID: "u", CreatedAt: time.Now()}); d != Queued {
		t.Fatalf("after pause %s", d)
	}
	flush(t, c)
	if s := c.Stats(); s.Attached != 1 || s.Failed[ReasonServer] != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestQueueAndCacheAreBounded(t *testing.T) {
	gate := make(chan struct{})
	rec := &recorder{}
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) {
		<-gate
		_, _ = w.Write([]byte(`{"status":"duplicate"}`))
	})
	c := client(t, srv.URL, Config{QueueSize: 2, CacheSize: 2})
	c.mu.Lock() // hold the worker so the queue fills deterministically
	c.running = true
	c.mu.Unlock()
	var got []Decision
	for _, u := range []string{"a", "b", "c"} {
		got = append(got, c.Signup(Signup{UserID: u, CreatedAt: time.Now()}))
	}
	if got[0] != Queued || got[1] != Queued || got[2] != Dropped || c.Stats().Dropped != 1 {
		t.Fatalf("decisions %v stats %+v", got, c.Stats())
	}
	go c.pump()
	close(gate)
	flush(t, c)
	c.Signup(Signup{UserID: "c", CreatedAt: time.Now()})
	flush(t, c)
	// a was least recently used, so it was forgotten when c arrived.
	if d := c.Signup(Signup{UserID: "a", CreatedAt: time.Now()}); d != Queued {
		t.Fatalf("evicted a: %s", d)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := c.Signup(Signup{UserID: "z", CreatedAt: time.Now()}); d != Disabled {
		t.Fatalf("after close %s", d)
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	var at []time.Time
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		at = append(at, time.Now())
		n := len(at)
		mu.Unlock()
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"status":"attached"}`))
	}))
	defer srv.Close()
	c := client(t, srv.URL, Config{})
	if s, err := c.Milestone(context.Background(), Milestone{UserID: "u", EventName: "x"}); err != nil || s != Attached {
		t.Fatalf("status %q err %v", s, err)
	}
	if gap := at[1].Sub(at[0]); gap < time.Second {
		t.Fatalf("retried after %s, before Retry-After", gap)
	}
}

func TestDeadlineCapsTheWholeSend(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	defer srv.Close()
	defer close(stop)
	c := client(t, srv.URL, Config{Timeout: 200 * time.Millisecond, Deadline: 300 * time.Millisecond, Retries: 5})
	start := time.Now()
	_, err := c.Milestone(context.Background(), Milestone{UserID: "u", EventName: "x"})
	var me *Error
	if !errors.As(err, &me) || me.Code != "TIMEOUT" || me.Reason() != ReasonTimeout {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

// A 200 whose body is cut off mid-read is a transport failure to retry, not
// an HTTP error: Motif committed, and the retry answers duplicate.
func TestCutOffBodyRetriesInsteadOfFalseError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			hj, _ := w.(http.Hijacker)
			conn, buf, _ := hj.Hijack()
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"sta")
			_ = buf.Flush()
			_ = conn.(*net.TCPConn).Close()
			return
		}
		_, _ = w.Write([]byte(`{"status":"duplicate"}`))
	}))
	defer srv.Close()
	c := client(t, srv.URL, Config{})
	s, err := c.Milestone(context.Background(), Milestone{UserID: "u", EventName: "x"})
	if err != nil || s != Duplicate || calls.Load() != 2 {
		t.Fatalf("status %q err %v calls %d", s, err, calls.Load())
	}
}

func TestCompleteNonJSONBodyIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("<html>proxy page</html>"))
	}))
	defer srv.Close()
	c := client(t, srv.URL, Config{})
	_, err := c.Milestone(context.Background(), Milestone{UserID: "u", EventName: "x"})
	var me *Error
	if !errors.As(err, &me) || me.StatusCode != 200 || me.Code != "HTTP_ERROR" || calls.Load() != 1 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}
}

func TestInvalidSignupPausesForTheCacheTTL(t *testing.T) {
	rec := &recorder{}
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"INVALID","message":"user_id too long"}`))
	})
	c := client(t, srv.URL, Config{})
	c.Signup(Signup{UserID: "u", CreatedAt: time.Now()})
	flush(t, c)
	c.mu.Lock()
	for _, el := range c.cache {
		if left := time.Until(el.Value.(*entry).until); left < time.Hour {
			t.Fatalf("a refused request pauses only %s", left)
		}
	}
	c.mu.Unlock()
}

func TestBackfillSendsCreatedAtAndReportsEveryUser(t *testing.T) {
	var rec recorder
	srv := rec.serve(t, func(n int, w http.ResponseWriter) {
		if n == 1 {
			_, _ = w.Write([]byte(`{"status":"attached"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	})
	var kinds []string
	var mu sync.Mutex
	c := client(t, srv.URL, Config{BackfillRate: 20, OnResult: func(r Result) { mu.Lock(); kinds = append(kinds, r.Kind+":"+r.Outcome); mu.Unlock() }})
	day := 24 * time.Hour
	createdA := time.Now().Add(-60 * day).Truncate(time.Second)
	rep, err := c.Backfill(context.Background(), []Signup{
		{UserID: "a", CreatedAt: createdA},
		{UserID: "b", CreatedAt: time.Now().Add(-3 * day)},
		{UserID: "old", CreatedAt: time.Now().Add(-91 * day)},
		{UserID: "", CreatedAt: time.Now()},
		{UserID: "zero"},
		{UserID: "future", CreatedAt: time.Now().Add(day)},
		{UserID: "a", CreatedAt: createdA},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := BackfillReport{Total: 7, Eligible: 2, Sent: BackfillSent{Attached: 1, Pending: 1}, Duplicate: 1, TooOld: 1, Invalid: 3, Failed: map[string]int{}}
	if got, _ := json.Marshal(rep); string(got) != string(must(json.Marshal(want))) {
		t.Fatalf("report %s", got)
	}
	if b := rec.bodies[0]; b["user_id"] != "a" || b["event_name"] != "signup_completed" || b["occurred_at"] != createdA.UTC().Format(time.RFC3339) || b["dedupe_key"] != nil {
		t.Fatalf("body %v", b)
	}
	if strings.Join(kinds, ",") != "backfill:attached,backfill:pending" {
		t.Fatalf("results %v", kinds)
	}
	// A backfilled user is acknowledged: Signup for them costs no request.
	if d := c.Signup(Signup{UserID: "a", CreatedAt: time.Now()}); d != Known {
		t.Fatalf("signup after backfill: %s", d)
	}
}

func TestBackfillIsIdempotentWithSignup(t *testing.T) {
	var mu sync.Mutex
	stored := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		key := b["website_id"].(string) + "|" + b["user_id"].(string) + "|" + b["event_name"].(string)
		if d, ok := b["dedupe_key"].(string); ok {
			key += "|" + d
		}
		mu.Lock()
		dup := stored[key]
		stored[key] = true
		mu.Unlock()
		if dup {
			_, _ = w.Write([]byte(`{"status":"duplicate"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()
	live := client(t, srv.URL, Config{})
	live.Signup(Signup{UserID: "u1", CreatedAt: time.Now().Add(-time.Hour)})
	flush(t, live)
	repair := client(t, srv.URL, Config{BackfillRate: 20})
	rep, err := repair.Backfill(context.Background(), []Signup{
		{UserID: "u1", CreatedAt: time.Now().Add(-time.Hour)},
		{UserID: "u2", CreatedAt: time.Now().Add(-10 * 24 * time.Hour)},
	})
	if err != nil || rep.Duplicate != 1 || rep.Sent.Pending != 1 {
		t.Fatalf("report %+v err %v", rep, err)
	}
}

func TestBackfillHonoursRetryAfterAndStopsOnARefusedKey(t *testing.T) {
	var rec recorder
	srv := rec.serve(t, func(n int, w http.ResponseWriter) {
		switch n {
		case 1:
			w.Header().Set("Retry-After", "0.3")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			_, _ = w.Write([]byte(`{"status":"attached"}`))
		case 3:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"VALIDATION_ERROR","message":"no"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	c := client(t, srv.URL, Config{BackfillRate: 20})
	var users []Signup
	for _, u := range []string{"a", "b", "c", "d", "e"} {
		users = append(users, Signup{UserID: u, CreatedAt: time.Now().Add(-time.Hour)})
	}
	start := time.Now()
	rep, err := c.Backfill(context.Background(), users)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatalf("did not wait for Retry-After")
	}
	if rep.Sent.Attached != 1 || rep.Failed[ReasonInvalid] != 1 || rep.Failed[ReasonConfig] != 3 || rec.count() != 4 {
		t.Fatalf("report %+v calls %d", rep, rec.count())
	}
}

func TestBackfillStopsWhenTheContextEnds(t *testing.T) {
	var rec recorder
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) { _, _ = w.Write([]byte(`{"status":"pending"}`)) })
	c := client(t, srv.URL, Config{BackfillRate: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rep, err := c.Backfill(ctx, []Signup{{UserID: "a", CreatedAt: time.Now()}, {UserID: "b", CreatedAt: time.Now()}})
	if !errors.Is(err, context.DeadlineExceeded) || rep.Sent.Pending != 1 || rec.count() != 1 {
		t.Fatalf("report %+v err %v calls %d", rep, err, rec.count())
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestBackfillEndsFastAfterARefusedKeyAndReportsEveryUser(t *testing.T) {
	var rec recorder
	srv := rec.serve(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) })
	var mu sync.Mutex
	var failed []string
	c := client(t, srv.URL, Config{BackfillRate: 1, OnResult: func(r Result) {
		mu.Lock()
		failed = append(failed, r.UserID+":"+r.Reason)
		mu.Unlock()
	}})
	start := time.Now()
	rep, err := c.Backfill(context.Background(), []Signup{
		{UserID: "a", CreatedAt: time.Now()}, {UserID: "b", CreatedAt: time.Now()}, {UserID: "c", CreatedAt: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	// At 1 per second, pacing the two refused users would take 2s.
	if d := time.Since(start); d > time.Second {
		t.Fatalf("backfill took %s after the key was refused", d)
	}
	if rep.Failed[ReasonConfig] != 3 || rec.count() != 1 || c.Stats().Failed[ReasonConfig] != 3 {
		t.Fatalf("report %+v calls %d stats %+v", rep, rec.count(), c.Stats())
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(failed, ",") != "a:config,b:config,c:config" {
		t.Fatalf("results %v", failed)
	}
}

func TestSignupOptedOutSendsNothing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()
	c, err := NewClient(Config{APIKey: "mtk_test_" + strings.Repeat("a", 32), WebsiteID: "11111111-1111-4111-8111-111111111111", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	if d := c.Signup(Signup{UserID: "u1", CreatedAt: time.Now(), OptedOut: true}); d != OptedOut {
		t.Fatalf("decision = %q, want %q", d, OptedOut)
	}
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("sent %d requests for an opted-out user", hits)
	}
	if got := c.Stats().Skipped[OptedOut]; got != 1 {
		t.Fatalf("Skipped[OptedOut] = %d, want 1", got)
	}
}
