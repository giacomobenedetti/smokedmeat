// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/stretchr/testify/assert"
)

func TestParseGateExpression(t *testing.T) {
	tests := []struct {
		name       string
		expr       string
		injSource  string
		solvable   bool
		triggers   []string
		unsolvable string
	}{
		{
			name:     "empty expression",
			expr:     "",
			solvable: true,
		},
		{
			name:      "contains controllable field",
			expr:      "contains(github.event.comment.body, '@whooli-bot analyze')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"@whooli-bot analyze"},
		},
		{
			name:      "equality controllable field",
			expr:      "github.event.comment.body == 'deploy'",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"deploy"},
		},
		{
			name:      "startsWith controllable field",
			expr:      "startsWith(github.event.issue.title, '[DEPLOY]')",
			injSource: "github.event.issue.title",
			solvable:  true,
			triggers:  []string{"[DEPLOY]"},
		},
		{
			name:      "AND both solvable",
			expr:      "contains(github.event.comment.body, '/approve') && contains(github.event.comment.body, 'LGTM')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/approve", "LGTM"},
		},
		{
			name:      "OR picks first solvable branch",
			expr:      "contains(github.event.comment.body, '/run') || contains(github.event.comment.body, '/exec')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/run"},
		},
		{
			name:       "non-controllable actor comparison",
			expr:       "github.actor == 'dependabot[bot]'",
			injSource:  "github.event.comment.body",
			solvable:   false,
			unsolvable: "actor is not attacker-controllable",
		},
		{
			name:       "negation of controllable contains",
			expr:       "!contains(github.event.comment.body, 'skip')",
			injSource:  "github.event.comment.body",
			solvable:   false,
			unsolvable: "negation of controllable condition",
		},
		{
			name:       "canceled func is unreachable", //nolint:misspell // cancelled is the GHA function name
			expr:       "cancelled()",                  //nolint:misspell // GitHub Actions uses British spelling
			injSource:  "github.event.comment.body",
			solvable:   false,
			unsolvable: "canceled() is unreachable",
		},
		{
			name:      "always is reachable",
			expr:      "always()",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "success is reachable",
			expr:      "success()",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "failure is reachable",
			expr:      "failure()",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "expression wrapper stripped",
			expr:      "${{ contains(github.event.comment.body, '/deploy') }}",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/deploy"},
		},
		{
			name:      "double-quoted string",
			expr:      `contains(github.event.comment.body, "/run")`,
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/run"},
		},
		{
			name:      "single-quoted string",
			expr:      "contains(github.event.comment.body, '/run')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/run"},
		},
		{
			name:      "nested parens",
			expr:      "(contains(github.event.comment.body, '/run'))",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/run"},
		},
		{
			name:      "OR with unsolvable first branch",
			expr:      "github.actor == 'bot' || contains(github.event.comment.body, '/run')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/run"},
		},
		{
			name:      "inequality with controllable field",
			expr:      "github.event.comment.body != ''",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "repository comparison is solvable (target known)",
			expr:      "github.repository == 'owner/repo'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "pr title controllable",
			expr:      "contains(github.event.pull_request.title, 'fix:')",
			injSource: "github.event.pull_request.title",
			solvable:  true,
			triggers:  []string{"fix:"},
		},
		{
			name:      "head_ref controllable",
			expr:      "startsWith(github.head_ref, 'feature/')",
			injSource: "github.head_ref",
			solvable:  true,
			triggers:  []string{"feature/"},
		},
		{
			name:      "inputs controllable",
			expr:      "github.event.inputs.action == 'deploy'",
			injSource: "github.event.inputs.action",
			solvable:  true,
			triggers:  []string{"deploy"},
		},
		{
			name:      "always with AND",
			expr:      "always() && contains(github.event.comment.body, '/run')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/run"},
		},
		{
			name:      "contains with body shorthand matches injection source",
			expr:      "contains(github.event.comment.body, '/approve')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/approve"},
		},
		{
			name:      "event_name check is trigger-implied",
			expr:      "github.event_name == 'issue_comment'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "event_name with AND still extracts trigger from controllable part",
			expr:      "github.event_name == 'issue_comment' && contains(github.event.comment.body, '/deploy')",
			injSource: "github.event.comment.body",
			solvable:  true,
			triggers:  []string{"/deploy"},
		},
		{
			name:      "event.action is trigger-implied",
			expr:      "github.event.action == 'created'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "contains event_name is trigger-implied",
			expr:      "contains(github.event_name, 'comment')",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "repository comparison is trigger-implied",
			expr:      "github.repository == 'owner/repo'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "repository_owner is trigger-implied",
			expr:      "github.repository_owner == 'myorg'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "author_association is trigger-implied",
			expr:      "github.event.comment.author_association == 'MEMBER'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "pr head ref controllable via event object",
			expr:      "startsWith(github.event.pull_request.head.ref, 'feature/')",
			injSource: "github.event.pull_request.head.ref",
			solvable:  true,
			triggers:  []string{"feature/"},
		},
		{
			name:      "pr head repo full_name controllable",
			expr:      "github.event.pull_request.head.repo.full_name == 'attacker/fork'",
			injSource: "github.event.pull_request.head.repo.full_name",
			solvable:  true,
			triggers:  []string{"attacker/fork"},
		},
		{
			name:      "merged is false at exploit time — eq false is solvable",
			expr:      "github.event.pull_request.merged == 'false'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:       "merged is false at exploit time — eq true is unsolvable",
			expr:       "github.event.pull_request.merged == 'true'",
			injSource:  "github.event.comment.body",
			solvable:   false,
			unsolvable: "is false at exploit time",
		},
		{
			name:      "merged != true is solvable",
			expr:      "github.event.pull_request.merged != 'true'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "head.fork is true at exploit time — eq true is solvable",
			expr:      "github.event.pull_request.head.fork == 'true'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:       "head.fork is true — eq false is unsolvable",
			expr:       "github.event.pull_request.head.fork == 'false'",
			injSource:  "github.event.comment.body",
			solvable:   false,
			unsolvable: "is true at exploit time",
		},
		{
			name:      "draft is false at exploit time",
			expr:      "github.event.pull_request.draft == 'false'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
		{
			name:      "label name is solvable via social engineering",
			expr:      "github.event.label.name == 'approved'",
			injSource: "github.event.comment.body",
			solvable:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gc := ParseGateExpression(tt.expr, tt.injSource)
			assert.Equal(t, tt.solvable, gc.Solvable, "solvable mismatch")
			if tt.triggers != nil {
				assert.Equal(t, tt.triggers, gc.Triggers, "triggers mismatch")
			} else {
				assert.Nil(t, gc.Triggers, "expected no triggers")
			}
			if tt.unsolvable != "" {
				assert.Contains(t, gc.Unsolvable, tt.unsolvable, "unsolvable reason mismatch")
			}
		})
	}
}

func TestExtractGateForFinding(t *testing.T) {
	workflows := []models.GithubActionsWorkflow{
		{
			Path: ".github/workflows/ci.yml",
			Jobs: []models.GithubActionsJob{
				{
					ID: "analyze",
					If: "contains(github.event.comment.body, '@whooli-bot analyze')",
					Steps: []models.GithubActionsStep{
						{
							Name: "Run analysis",
							Run:  "echo ${{ github.event.comment.body }}",
						},
					},
				},
			},
		},
		{
			Path: ".github/workflows/deploy.yml",
			Jobs: []models.GithubActionsJob{
				{
					ID: "deploy",
					Steps: []models.GithubActionsStep{
						{
							Name: "Deploy",
							If:   "github.actor == 'dependabot[bot]'",
							Run:  "deploy",
						},
					},
				},
			},
		},
	}

	t.Run("job gate extracts triggers", func(t *testing.T) {
		gc := extractGateForFinding(
			workflows,
			".github/workflows/ci.yml", "analyze", "",
			[]string{"github.event.comment.body"},
		)
		assert.True(t, gc.Solvable)
		assert.Equal(t, []string{"@whooli-bot analyze"}, gc.Triggers)
	})

	t.Run("step gate unsolvable", func(t *testing.T) {
		gc := extractGateForFinding(
			workflows,
			".github/workflows/deploy.yml", "deploy", "Deploy",
			[]string{"github.event.comment.body"},
		)
		assert.False(t, gc.Solvable)
		assert.Contains(t, gc.Unsolvable, "actor")
	})

	t.Run("no matching workflow", func(t *testing.T) {
		gc := extractGateForFinding(
			workflows,
			".github/workflows/unknown.yml", "job", "",
			[]string{"github.event.comment.body"},
		)
		assert.True(t, gc.Solvable)
		assert.Nil(t, gc.Triggers)
	})

	t.Run("no if conditions", func(t *testing.T) {
		wfs := []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/simple.yml",
				Jobs: []models.GithubActionsJob{
					{ID: "build"},
				},
			},
		}
		gc := extractGateForFinding(wfs, ".github/workflows/simple.yml", "build", "", nil)
		assert.True(t, gc.Solvable)
		assert.Nil(t, gc.Triggers)
	})

	t.Run("combined job and step gates", func(t *testing.T) {
		wfs := []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/gated.yml",
				Jobs: []models.GithubActionsJob{
					{
						ID: "gated",
						If: "contains(github.event.comment.body, '/run')",
						Steps: []models.GithubActionsStep{
							{
								Name: "exec",
								If:   "contains(github.event.comment.body, 'confirm')",
								Run:  "echo test",
							},
						},
					},
				},
			},
		}
		gc := extractGateForFinding(
			wfs,
			".github/workflows/gated.yml", "gated", "exec",
			[]string{"github.event.comment.body"},
		)
		assert.True(t, gc.Solvable)
		assert.Equal(t, []string{"/run", "confirm"}, gc.Triggers)
	})
}

func TestTokenizer(t *testing.T) {
	tokens := tokenize("contains(github.event.comment.body, '@whooli-bot analyze') && success()")
	kinds := make([]tokenKind, len(tokens))
	for i, tok := range tokens {
		kinds[i] = tok.kind
	}
	expected := []tokenKind{
		tokIdent,  // contains
		tokLParen, // (
		tokIdent,  // github.event.comment.body
		tokComma,  // ,
		tokString, // @whooli-bot analyze
		tokRParen, // )
		tokAnd,    // &&
		tokIdent,  // success
		tokLParen, // (
		tokRParen, // )
	}
	assert.Equal(t, expected, kinds)
}

func TestStripExpressionWrapper(t *testing.T) {
	assert.Equal(t, "contains(x, 'y')", stripExpressionWrapper("${{ contains(x, 'y') }}"))
	assert.Equal(t, "contains(x, 'y')", stripExpressionWrapper("contains(x, 'y')"))
	assert.Equal(t, "", stripExpressionWrapper(""))
}
