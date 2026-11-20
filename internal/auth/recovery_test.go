package auth

import (
	"context"
	"testing"
)

func TestMFARecoveryCodes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pActive, _ := e.owner(t)

	codes, err := e.s.RegenerateRecoveryCodes(ctx, pActive)
	if err != nil {
		t.Fatalf("regenerate recovery codes: %v", err)
	}
	if len(codes) != 8 {
		t.Fatalf("expected 8 codes, got %d", len(codes))
	}
	cnt, err := e.s.RecoveryCodeCount(ctx, pActive.UserID)
	if err != nil || cnt != 8 {
		t.Fatalf("expected count 8, got %d (%v)", cnt, err)
	}

	// Second login -> pending_mfa -> use recovery code
	pendIss, err := e.s.Login(ctx, "owner", goodPW, ci)
	if err != nil || pendIss.Stage != "pending_mfa" {
		t.Fatalf("second login: %v %+v", err, pendIss)
	}
	pPending, err := e.s.AuthenticateSession(ctx, pendIss.Token)
	if err != nil {
		t.Fatalf("auth pending: %v", err)
	}
	if _, err := e.s.VerifyMFA(ctx, pPending, codes[0], ci); err != nil {
		t.Fatalf("verify with recovery code failed: %v", err)
	}
	cnt, _ = e.s.RecoveryCodeCount(ctx, pActive.UserID)
	if cnt != 7 {
		t.Fatalf("expected 7 remaining codes, got %d", cnt)
	}
	// Reusing the same recovery code must fail
	pendIss2, _ := e.s.Login(ctx, "owner", goodPW, ci)
	pPending2, _ := e.s.AuthenticateSession(ctx, pendIss2.Token)
	if _, err := e.s.VerifyMFA(ctx, pPending2, codes[0], ci); err == nil {
		t.Fatal("expected error when reusing consumed recovery code")
	}
}
