package riskgate

import (
	"context"
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
	"time"
)

// Generated from the pinned reference's pure evaluators, not hand-written
// expectations. The source requests are synthetic and contain no private data.
func TestVM2APIPinnedBehaviorGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/vm2api_alignment_golden.json")
	require.NoError(t, err)
	var cases struct {
		Commit string `json:"reference_commit"`
		Rules  []struct {
			ID, Text string
			Expected *struct {
				Category string `json:"category"`
			}
		} `json:"hard_rules"`
		Scoring []struct {
			ID        string
			Scores    map[string]float64
			Threshold float64
			Below     bool `json:"block_if_below"`
			Expected  struct {
				Hits []struct {
					Category string
					Score    float64
				}
			}
		} `json:"scoring"`
		Distill []struct {
			ID    string
			Body  json.RawMessage
			Flags struct {
				Official   bool
				ZeroInject bool
			}
			Rules struct {
				Enabled                         bool
				SkipOfficial                    bool     `json:"skip_official"`
				SkipZero                        bool     `json:"skip_zero"`
				HardNeedles                     []string `json:"hard_needles"`
				Needles, Patterns, Fingerprints []string
				Error                           ResponseErrorConfig
				Structure                       struct {
					Min     int    `json:"min_max_tokens"`
					NoTools bool   `json:"require_no_tools"`
					Single  bool   `json:"require_single_turn"`
					Pattern string `json:"contest_pattern"`
				}
			}
			Expected *struct {
				Action string
				Hits   []struct{ Rule, Evidence string }
			}
		} `json:"distill"`
		Documents []struct {
			ID       string
			Body     json.RawMessage
			Expected string
		} `json:"documents"`
	}
	require.NoError(t, json.Unmarshal(raw, &cases))
	require.Equal(t, "9ec89afb3ae6412e993fe61f02b4d5c140d1b627", cases.Commit)
	for _, tc := range cases.Rules {
		t.Run("regex/"+tc.ID, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Gates.Regex = true
			cfg.Gates.Distill = true
			hit, _ := evaluatePolicyRules(cfg, TextView{UserTranscript: tc.Text}, BuiltinRules(), newRegexCache(), false)
			require.Equal(t, tc.Expected != nil, hit.Hit)
			if tc.Expected != nil {
				require.Equal(t, tc.Expected.Category, hit.Category)
			}
		})
	}
	for _, tc := range cases.Scoring {
		t.Run("score/"+tc.ID, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DecisionModel.SafetyThreshold = tc.Threshold
			cfg.DecisionModel.BlockIfBelow = tc.Below
			hit := safetyDecision(cfg, "synthetic fixture", tc.Scores)
			require.Equal(t, len(tc.Expected.Hits) > 0, hit.Hit)
			if hit.Hit {
				categories := []string{}
				for _, expected := range tc.Expected.Hits {
					categories = append(categories, expected.Category)
				}
				require.Contains(t, categories, hit.Category)
			}
		})
	}
	for _, tc := range cases.Distill {
		t.Run("distill/"+tc.ID, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Gates.Distill = true
			cfg.Distill = DistillConfig{HardNeedles: tc.Rules.HardNeedles, Needles: tc.Rules.Needles, Patterns: tc.Rules.Patterns, Fingerprints: tc.Rules.Fingerprints, SkipOfficial: tc.Rules.SkipOfficial, SkipZero: tc.Rules.SkipZero, MinMaxTokens: tc.Rules.Structure.Min, ContestPattern: tc.Rules.Structure.Pattern, RequireNoTools: tc.Rules.Structure.NoTools, RequireSingleTurn: tc.Rules.Structure.Single, Error: tc.Rules.Error}
			view, meta, err := BuildTextView(securityaudit.Request{Body: tc.Body, Protocol: "anthropic", Model: "claude-test"}, NormalizeOptions{})
			require.NoError(t, err)
			var root struct{ Model string }
			require.NoError(t, json.Unmarshal(tc.Body, &root))
			hit := GateResult{}
			if !isOpenAI("", root.Model) {
				hit, _ = evaluateDistillRules(cfg, view, meta, Identity{OfficialClaudeCode: tc.Flags.Official, ZeroInjection: tc.Flags.ZeroInject}, newRegexCache(), nil)
			}
			require.Equal(t, tc.Expected != nil && tc.Expected.Action == "block", hit.Hit)
			if hit.Hit {
				require.Equal(t, tc.Expected.Hits[0].Evidence, hit.Evidence)
			}
		})
	}
	for _, tc := range cases.Documents {
		t.Run("document/"+tc.ID, func(t *testing.T) {
			turns, labels, _, _ := requestUserTurns(tc.Body)
			require.Equal(t, tc.Expected, modelUserDocument(turns, labels, 16000, true))
		})
	}
}

func TestAlignmentAccountScopeDefersAndUsesRealSelectedIdentity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "blocking"
	cfg.Gates.Regex = true
	cfg.Scope.AccountPlatformPlans = []string{"claude:max"}
	cfg.Scope.AccountIDs = []string{"fixture@example.test"}
	source := &fakeConfigSource{config: cfg, ready: true}
	rules := &fakeRuleSource{rules: []Rule{{ID: 77, Gate: GateRegex, Category: "custom", Pattern: "fixture_trigger", Enabled: true, Action: "block"}}}
	bans := newFakeBanResolver()
	sink := &recordingSink{}
	engine, err := NewEngine(source, rules, bans, sink, nil, nil)
	require.NoError(t, err)
	req := securityaudit.Request{RequestID: "scope-fixture", APIKeyID: 1, UserID: 2, Provider: "anthropic", Protocol: "anthropic", Model: "claude-test", Stage: "http", Body: []byte(`{"model":"claude-test","messages":[{"role":"user","content":"fixture_trigger"}]}`)}
	require.Nil(t, engine.Decide(context.Background(), req))
	require.Zero(t, rules.Calls(), "must not run before actual account selection")
	req.SelectedAccountID = 1
	req.SelectedAccountPlatform = "anthropic"
	req.SelectedAccountPlan = "pro"
	require.Nil(t, engine.DecideSelected(context.Background(), req))
	require.Zero(t, rules.Calls(), "out-of-scope accounts skip rules")
	req.SelectedAccountPlan = "max"
	decision := engine.DecideSelected(context.Background(), req)
	require.NotNil(t, decision)
	require.False(t, decision.AllowNextStage)
	req.SelectedAccountPlan = "pro"
	req.SelectedAccountEmail = "FIXTURE@example.test"
	require.NotNil(t, engine.DecideSelected(context.Background(), req), "specified identity and plan selectors form a case-insensitive union")
	source.config.Scope.AccountPlatformPlans = nil
	source.config.Scope.AccountIDs = nil
	calls := rules.Calls()
	require.Nil(t, engine.DecideSelected(context.Background(), req))
	require.Equal(t, calls, rules.Calls(), "unscoped check must not run twice")
}
func TestAlignmentDeviceBansRespectToggleAndNeverInferFromUserAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "blocking"
	cfg.RefusalCache.DeviceBlockEnabled = true
	req := securityaudit.Request{APIKeyID: 1, UserID: 2, InboundDeviceID: "fixture-device-001", ClientFingerprint: "shared-agent-fingerprint"}
	bans := newFakeBanResolver()
	subject := inboundFingerprint(req)
	require.NotEmpty(t, subject)
	require.NotEqual(t, req.InboundDeviceID, subject)
	bans.add(Ban{Scope: BanScopeClientFingerprint, Subject: subject})
	hit, err := evaluateBan(context.Background(), cfg, req, bans, time.Now())
	require.NoError(t, err)
	require.True(t, hit.Hit)
	cfg.RefusalCache.DeviceBlockEnabled = false
	hit, err = evaluateBan(context.Background(), cfg, req, bans, time.Now())
	require.NoError(t, err)
	require.False(t, hit.Hit)
	cfg.RefusalCache.DeviceBlockEnabled = true
	req.InboundDeviceID = ""
	require.Empty(t, inboundFingerprint(req))
	hit, err = evaluateBan(context.Background(), cfg, req, bans, time.Now())
	require.NoError(t, err)
	require.False(t, hit.Hit)
}
func TestAlignmentObserveRuleContinuesIntoLaterBlock(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "blocking"
	cfg.Gates.Regex = true
	rules := []Rule{{ID: 1, Gate: GateRegex, Category: "custom", Pattern: "fixture", Enabled: true, Action: "observe"}, {ID: 2, Gate: GateRegex, Category: "custom", Pattern: "fixture", Enabled: true, Action: "block"}}
	hit, observations := evaluatePolicyRules(cfg, TextView{UserTranscript: "fixture"}, rules, newRegexCache(), false)
	require.True(t, hit.Hit)
	require.EqualValues(t, 2, hit.RuleID)
	require.Len(t, observations, 1)
	require.False(t, observations[0].BanSignal)
}
func TestAlignmentModelDocumentKeepsCurrentAskAtBudget(t *testing.T) {
	doc := modelUserDocument([]string{strings.Repeat("old text ", 300), "LATEST_QUESTION"}, []string{"user message 1", "user message 3"}, 256, true)
	require.LessOrEqual(t, len([]rune(doc)), 256)
	require.Contains(t, doc, "[current ask]")
	require.True(t, strings.HasSuffix(doc, "latest_question"))
}
