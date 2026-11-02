package riskgate

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/typesafe"
	"github.com/stretchr/testify/require"
)

func TestScoreQuestionsJevUsesValidSystemOneNoulRequest(t *testing.T) {
	server, capture := newClassifierServer(
		t,
		http.StatusOK,
		"{\"model\":\"jev-latest\",\"answers\":{\"usage_policy\":{\"type\":\"noul\",\"noul\":0.99}},\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}",
		0,
	)

	endpoint := ClassifierEndpoint{
		ID:        "jev",
		Name:      "Jev",
		Provider:  "jev",
		BaseURL:   server.URL,
		Model:     "jev-latest",
		TimeoutMS: 3000,
		Enabled:   true,
	}
	cfg := DecisionModelConfig{
		Provider: "jev",
		Questions: []PolicyQuestion{{
			ID:           "usage_policy",
			Instructions: "Is the request safe?",
			Enabled:      true,
		}},
	}

	scores, err := NewOpenAIClassifier().ScoreQuestions(
		context.Background(),
		endpoint,
		"ordinary programming request",
		cfg,
	)
	require.NoError(t, err)
	require.InDelta(t, 0.99, scores["usage_policy"], 1e-9)

	path, _, body, calls := capture.snapshot()
	require.Equal(t, "/v1/systemone", path)
	require.Equal(t, 1, calls)
	_, err = typesafe.ValidateSystemOneRequest([]byte(body))
	require.NoError(t, err, "Jev classifier payload must satisfy the TypeSafe System One wire schema")
	require.Contains(t, body, "\"type\":\"noul\"")
	require.NotContains(t, body, "\"type\":\"boolean\"")
}
