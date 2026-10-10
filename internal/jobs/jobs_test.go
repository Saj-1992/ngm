package jobs

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/ngm-gateway/ngm/internal/store/storetest"
)

func TestHappyPathJournal(t *testing.T) {
	ctx := context.Background()
	j := NewJournal(storetest.New(t))
	job, created, err := j.Submit(ctx, SubmitRequest{Kind: "deploy", ActorID: "u1", LockSet: []string{"gateway-config"}, Payload: map[string]int{"rev": 3}})
	if err != nil || !created || job.State != Queued {
		t.Fatalf("submit: %+v %v %v", job, created, err)
	}
	path := []State{Queued, Validating, ImpactAnalyzed, Staging, Preflight, Applying, Verifying, Succeeded}
	for i := 1; i < len(path); i++ {
		cls := Idempotent
		if path[i] == Applying {
			cls = External
		}
		job, err = j.Transition(ctx, job.ID, path[i-1], path[i], TransitionOpts{Class: cls, Evidence: map[string]int{"i": i}})
		if err != nil {
			t.Fatalf("%s->%s: %v", path[i-1], path[i], err)
		}
	}
	if job.State != Succeeded || job.FinishedAt == nil || job.StartedAt == nil || job.Attempts != 1 {
		t.Fatalf("final job %+v", job)
	}
	steps, err := j.Steps(ctx, job.ID)
	if err != nil || len(steps) != len(path)-1 {
		t.Fatalf("steps=%d err=%v", len(steps), err)
	}
	if steps[4].Class != External || steps[4].ToState != Applying {
		t.Fatalf("step 5 %+v", steps[4])
	}
}

func TestInvalidTransitionsRejected(t *testing.T) {
	ctx := context.Background()
	j := NewJournal(storetest.New(t))
	job, _, _ := j.Submit(ctx, SubmitRequest{Kind: "deploy"})
	if _, err := j.Transition(ctx, job.ID, Queued, Succeeded, TransitionOpts{}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Queued->Succeeded: %v", err)
	}
	if _, err := j.Transition(ctx, job.ID, Applying, Verifying, TransitionOpts{}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("CAS on wrong from-state should fail: %v", err)
	}
	if _, err := j.Transition(ctx, "nope", Queued, Validating, TransitionOpts{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing job: %v", err)
	}
	for _, s := range []State{Succeeded, Failed, Cancelled, RolledBack, Blocked} {
		for _, to := range []State{Queued, Validating, Applying} {
			if ValidTransition(s, to) {
				t.Errorf("terminal %s -> %s allowed", s, to)
			}
		}
	}
	if ValidTransition(Applying, Cancelled) {
		t.Error("cancellation after side effects must be forbidden")
	}
}

func TestCancelBoundary(t *testing.T) {
	ctx := context.Background()
	j := NewJournal(storetest.New(t))
	a, _, _ := j.Submit(ctx, SubmitRequest{Kind: "x"})
	if got, err := j.Cancel(ctx, a.ID, "u"); err != nil || got.State != Cancelled {
		t.Fatalf("cancel queued: %v", err)
	}
	b, _, _ := j.Submit(ctx, SubmitRequest{Kind: "x"})
	for _, p := range [][2]State{{Queued, Validating}, {Validating, ImpactAnalyzed}, {ImpactAnalyzed, Staging}, {Staging, Preflight}, {Preflight, Applying}} {
		if _, err := j.Transition(ctx, b.ID, p[0], p[1], TransitionOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.Cancel(ctx, b.ID, "u"); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("cancel applying: %v", err)
	}
}

func TestIdempotentSubmit(t *testing.T) {
	ctx := context.Background()
	j := NewJournal(storetest.New(t))
	a, c1, err := j.Submit(ctx, SubmitRequest{Kind: "backup", ActorID: "u1", IdempotencyKey: "key-12345"})
	if err != nil || !c1 {
		t.Fatal(err)
	}
	b, c2, err := j.Submit(ctx, SubmitRequest{Kind: "backup", ActorID: "u1", IdempotencyKey: "key-12345"})
	if err != nil || c2 || b.ID != a.ID {
		t.Fatalf("replay: id=%s created=%v err=%v", b.ID, c2, err)
	}
	c, c3, _ := j.Submit(ctx, SubmitRequest{Kind: "backup", ActorID: "u2", IdempotencyKey: "key-12345"})
	if !c3 || c.ID == a.ID {
		t.Fatal("key must be scoped per actor")
	}
}

func TestConcurrentTransitionOnlyOneWins(t *testing.T) {
	ctx := context.Background()
	j := NewJournal(storetest.New(t))
	job, _, _ := j.Submit(ctx, SubmitRequest{Kind: "x"})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := j.Transition(ctx, job.ID, Queued, Validating, TransitionOpts{}); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins=%d, want exactly 1", wins)
	}
}

func TestFenceRejectionAbortsTransition(t *testing.T) {
	ctx := context.Background()
	j := NewJournal(storetest.New(t))
	job, _, _ := j.Submit(ctx, SubmitRequest{Kind: "x"})
	stale := errors.New("stale fence")
	_, err := j.Transition(ctx, job.ID, Queued, Validating, TransitionOpts{Fence: func(context.Context, *sql.Tx) error { return stale }})
	if !errors.Is(err, stale) {
		t.Fatalf("got %v", err)
	}
	got, _ := j.Get(ctx, job.ID)
	if got.State != Queued {
		t.Fatalf("state changed despite fence failure: %s", got.State)
	}
}

func TestOpenExternalStepVisibleForReconciliation(t *testing.T) {
	ctx := context.Background()
	j := NewJournal(storetest.New(t))
	job, _, _ := j.Submit(ctx, SubmitRequest{Kind: "x"})
	tok := int64(7)
	sid, err := j.BeginStep(ctx, job.ID, "nginx-reload", External, &tok)
	if err != nil {
		t.Fatal(err)
	}
	un, _ := j.Unfinished(ctx)
	if len(un) != 1 {
		t.Fatalf("unfinished=%d", len(un))
	}
	steps, _ := j.Steps(ctx, job.ID)
	if steps[0].Status != "started" || steps[0].FinishedAt != nil {
		t.Fatalf("%+v", steps[0])
	}
	if err := j.FinishStep(ctx, sid, "completed", map[string]bool{"reloaded": true}); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishStep(ctx, sid, "completed", nil); err == nil {
		t.Fatal("double finish must fail")
	}
}
