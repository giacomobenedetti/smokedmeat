// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"strings"

	"github.com/boostsecurityio/poutine/models"
)

type GateConstraint struct {
	Expression string
	Solvable   bool
	Triggers   []string
	Unsolvable string
}

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokAnd
	tokOr
	tokEq
	tokNeq
	tokNot
	tokLParen
	tokRParen
	tokComma
	tokString
	tokIdent
)

type token struct {
	kind tokenKind
	val  string
}

func tokenize(input string) []token {
	var tokens []token
	i := 0
	for i < len(input) {
		ch := input[i]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}
		if ch == '&' && i+1 < len(input) && input[i+1] == '&' {
			tokens = append(tokens, token{tokAnd, "&&"})
			i += 2
			continue
		}
		if ch == '|' && i+1 < len(input) && input[i+1] == '|' {
			tokens = append(tokens, token{tokOr, "||"})
			i += 2
			continue
		}
		if ch == '=' && i+1 < len(input) && input[i+1] == '=' {
			tokens = append(tokens, token{tokEq, "=="})
			i += 2
			continue
		}
		if ch == '!' && i+1 < len(input) && input[i+1] == '=' {
			tokens = append(tokens, token{tokNeq, "!="})
			i += 2
			continue
		}
		if ch == '!' {
			tokens = append(tokens, token{tokNot, "!"})
			i++
			continue
		}
		if ch == '(' {
			tokens = append(tokens, token{tokLParen, "("})
			i++
			continue
		}
		if ch == ')' {
			tokens = append(tokens, token{tokRParen, ")"})
			i++
			continue
		}
		if ch == ',' {
			tokens = append(tokens, token{tokComma, ","})
			i++
			continue
		}
		if ch == '\'' || ch == '"' {
			quote := ch
			i++
			start := i
			for i < len(input) && input[i] != quote {
				i++
			}
			tokens = append(tokens, token{tokString, input[start:i]})
			if i < len(input) {
				i++
			}
			continue
		}
		if isIdentStart(ch) {
			start := i
			for i < len(input) && isIdentChar(input[i]) {
				i++
			}
			tokens = append(tokens, token{tokIdent, input[start:i]})
			continue
		}
		i++
	}
	return tokens
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isIdentChar(ch byte) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '*'
}

type nodeKind int

const (
	nodeOr nodeKind = iota
	nodeAnd
	nodeComparison
	nodeNegation
	nodeFuncCall
	nodeIdent
	nodeString
)

type astNode struct {
	kind     nodeKind
	op       string
	val      string
	children []*astNode
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{tokEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return t
}

func (p *parser) expect(kind tokenKind) token {
	t := p.next()
	if t.kind != kind {
		return t
	}
	return t
}

func (p *parser) parseExpr() *astNode {
	return p.parseOr()
}

func (p *parser) parseOr() *astNode {
	left := p.parseAnd()
	for p.peek().kind == tokOr {
		p.next()
		right := p.parseAnd()
		left = &astNode{kind: nodeOr, children: []*astNode{left, right}}
	}
	return left
}

func (p *parser) parseAnd() *astNode {
	left := p.parseComparison()
	for p.peek().kind == tokAnd {
		p.next()
		right := p.parseComparison()
		left = &astNode{kind: nodeAnd, children: []*astNode{left, right}}
	}
	return left
}

func (p *parser) parseComparison() *astNode {
	left := p.parseUnary()
	if p.peek().kind == tokEq || p.peek().kind == tokNeq {
		op := p.next()
		right := p.parseUnary()
		return &astNode{kind: nodeComparison, op: op.val, children: []*astNode{left, right}}
	}
	return left
}

func (p *parser) parseUnary() *astNode {
	if p.peek().kind == tokNot {
		p.next()
		child := p.parseUnary()
		return &astNode{kind: nodeNegation, children: []*astNode{child}}
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() *astNode {
	t := p.peek()
	switch t.kind {
	case tokString:
		p.next()
		return &astNode{kind: nodeString, val: t.val}
	case tokIdent:
		p.next()
		if p.peek().kind == tokLParen {
			p.next()
			var args []*astNode
			for p.peek().kind != tokRParen && p.peek().kind != tokEOF {
				args = append(args, p.parseExpr())
				if p.peek().kind == tokComma {
					p.next()
				}
			}
			p.expect(tokRParen)
			return &astNode{kind: nodeFuncCall, val: t.val, children: args}
		}
		return &astNode{kind: nodeIdent, val: t.val}
	case tokLParen:
		p.next()
		expr := p.parseExpr()
		p.expect(tokRParen)
		return expr
	default:
		p.next()
		return &astNode{kind: nodeIdent, val: t.val}
	}
}

func parse(input string) *astNode {
	tokens := tokenize(input)
	if len(tokens) == 0 {
		return nil
	}
	p := &parser{tokens: tokens}
	return p.parseExpr()
}

type evalResult struct {
	solvable   bool
	triggers   []string
	unsolvable string
}

var controllableFields = map[string]bool{
	"github.event.comment.body":                     true,
	"github.event.issue.title":                      true,
	"github.event.issue.body":                       true,
	"github.event.pull_request.title":               true,
	"github.event.pull_request.body":                true,
	"github.head_ref":                               true,
	"github.event.pull_request.head.ref":            true,
	"github.event.pull_request.head.repo.full_name": true,
}

var knownExploitValues = map[string]string{
	"github.event.pull_request.merged":    "false",
	"github.event.pull_request.head.fork": "true",
	"github.event.pull_request.draft":     "false",
}

func isControllable(field string) bool {
	if controllableFields[field] {
		return true
	}
	if strings.HasPrefix(field, "github.event.inputs.") {
		return true
	}
	return false
}

func isInjectionSourceControllable(field, injectionSource string) bool {
	if isControllable(field) {
		return true
	}
	if injectionSource != "" && strings.Contains(field, shortFieldName(injectionSource)) {
		return true
	}
	return false
}

func shortFieldName(source string) string {
	parts := strings.Split(source, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return source
}

func evaluate(node *astNode, injectionSource string) evalResult {
	if node == nil {
		return evalResult{solvable: true}
	}
	switch node.kind {
	case nodeOr:
		for _, child := range node.children {
			r := evaluate(child, injectionSource)
			if r.solvable {
				return r
			}
		}
		results := make([]evalResult, len(node.children))
		for i, child := range node.children {
			results[i] = evaluate(child, injectionSource)
		}
		return results[len(results)-1]

	case nodeAnd:
		var allTriggers []string
		for _, child := range node.children {
			r := evaluate(child, injectionSource)
			if !r.solvable {
				return r
			}
			allTriggers = append(allTriggers, r.triggers...)
		}
		return evalResult{solvable: true, triggers: allTriggers}

	case nodeNegation:
		inner := evaluate(node.children[0], injectionSource)
		if inner.solvable && len(inner.triggers) > 0 {
			return evalResult{solvable: false, unsolvable: "negation of controllable condition"}
		}
		if !inner.solvable {
			return evalResult{solvable: true}
		}
		return evalResult{solvable: true}

	case nodeFuncCall:
		return evaluateFunc(node, injectionSource)

	case nodeComparison:
		return evaluateComparison(node, injectionSource)

	case nodeIdent:
		if node.val == "true" {
			return evalResult{solvable: true}
		}
		if node.val == "false" {
			return evalResult{solvable: false, unsolvable: "literal false"}
		}
		if isInjectionSourceControllable(node.val, injectionSource) {
			return evalResult{solvable: true}
		}
		return evalResult{solvable: true}

	case nodeString:
		return evalResult{solvable: true}

	default:
		return evalResult{solvable: true}
	}
}

func evaluateFunc(node *astNode, injectionSource string) evalResult {
	name := strings.ToLower(node.val)
	switch name {
	case "contains":
		if len(node.children) < 2 {
			return evalResult{solvable: true}
		}
		field := identOrString(node.children[0])
		value := identOrString(node.children[1])
		if isTriggerImpliedField(field) || isTriggerImpliedField(value) {
			return evalResult{solvable: true}
		}
		if isInjectionSourceControllable(field, injectionSource) {
			if value != "" {
				return evalResult{solvable: true, triggers: []string{value}}
			}
			return evalResult{solvable: true}
		}
		if isInjectionSourceControllable(value, injectionSource) {
			return evalResult{solvable: true}
		}
		return evalResult{solvable: true}

	case "startswith":
		if len(node.children) < 2 {
			return evalResult{solvable: true}
		}
		field := identOrString(node.children[0])
		value := identOrString(node.children[1])
		if isTriggerImpliedField(field) {
			return evalResult{solvable: true}
		}
		if isInjectionSourceControllable(field, injectionSource) {
			if value != "" {
				return evalResult{solvable: true, triggers: []string{value}}
			}
			return evalResult{solvable: true}
		}
		return evalResult{solvable: true}

	case "endswith":
		if len(node.children) < 2 {
			return evalResult{solvable: true}
		}
		field := identOrString(node.children[0])
		value := identOrString(node.children[1])
		if isTriggerImpliedField(field) {
			return evalResult{solvable: true}
		}
		if isInjectionSourceControllable(field, injectionSource) {
			if value != "" {
				return evalResult{solvable: true, triggers: []string{value}}
			}
			return evalResult{solvable: true}
		}
		return evalResult{solvable: true}

	case "success", "always":
		return evalResult{solvable: true}

	case "failure":
		return evalResult{solvable: true}

	case "cancelled", "canceled": //nolint:misspell // GitHub Actions uses British spelling 'cancelled'
		return evalResult{solvable: false, unsolvable: "canceled() is unreachable"}

	case "format":
		return evalResult{solvable: true}

	default:
		return evalResult{solvable: true}
	}
}

func evaluateKnownValue(knownVal, comparedVal, op, fieldName string) evalResult {
	matches := strings.EqualFold(knownVal, comparedVal)
	switch op {
	case "==":
		if matches {
			return evalResult{solvable: true}
		}
		return evalResult{solvable: false, unsolvable: fieldName + " is " + knownVal + " at exploit time"}
	case "!=":
		if !matches {
			return evalResult{solvable: true}
		}
		return evalResult{solvable: false, unsolvable: fieldName + " is " + knownVal + " at exploit time"}
	}
	return evalResult{solvable: true}
}

func evaluateComparison(node *astNode, injectionSource string) evalResult {
	if len(node.children) < 2 {
		return evalResult{solvable: true}
	}
	left := identOrString(node.children[0])
	right := identOrString(node.children[1])

	if isTriggerImpliedField(left) || isTriggerImpliedField(right) {
		return evalResult{solvable: true}
	}

	if kv, ok := knownExploitValues[left]; ok && node.children[1].kind == nodeString {
		return evaluateKnownValue(kv, right, node.op, left)
	}
	if kv, ok := knownExploitValues[right]; ok && node.children[0].kind == nodeString {
		return evaluateKnownValue(kv, left, node.op, right)
	}

	leftControllable := isInjectionSourceControllable(left, injectionSource)
	rightControllable := isInjectionSourceControllable(right, injectionSource)

	switch node.op {
	case "==":
		if leftControllable && node.children[1].kind == nodeString {
			return evalResult{solvable: true, triggers: []string{right}}
		}
		if rightControllable && node.children[0].kind == nodeString {
			return evalResult{solvable: true, triggers: []string{left}}
		}
		if leftControllable || rightControllable {
			return evalResult{solvable: true}
		}
		if !leftControllable && !rightControllable {
			if isNonControllableField(left) || isNonControllableField(right) {
				return evalResult{solvable: false, unsolvable: nonControllableReason(left, right)}
			}
		}
		return evalResult{solvable: true}

	case "!=":
		if leftControllable && node.children[1].kind == nodeString {
			return evalResult{solvable: true}
		}
		if rightControllable && node.children[0].kind == nodeString {
			return evalResult{solvable: true}
		}
		if !leftControllable && !rightControllable {
			if isNonControllableField(left) || isNonControllableField(right) {
				return evalResult{solvable: false, unsolvable: nonControllableReason(left, right)}
			}
		}
		return evalResult{solvable: true}
	}

	return evalResult{solvable: true}
}

func isTriggerImpliedField(field string) bool {
	switch field {
	case "github.event_name", "github.event.action":
		return true
	case "github.repository", "github.repository_owner":
		return true
	case "github.event.comment.author_association":
		return true
	}
	return false
}

func isNonControllableField(field string) bool {
	if isTriggerImpliedField(field) {
		return false
	}
	nonControllable := []string{
		"github.actor",
		"github.ref",
		"github.base_ref",
	}
	for _, f := range nonControllable {
		if field == f {
			return true
		}
	}
	return false
}

func nonControllableReason(left, right string) string {
	for _, f := range []string{left, right} {
		if isNonControllableField(f) {
			last := f
			if idx := strings.LastIndex(f, "."); idx != -1 {
				last = f[idx+1:]
			}
			return last + " is not attacker-controllable"
		}
	}
	return "non-controllable field comparison"
}

func identOrString(node *astNode) string {
	if node == nil {
		return ""
	}
	switch node.kind {
	case nodeString:
		return node.val
	case nodeIdent:
		return node.val
	default:
		return ""
	}
}

func stripExpressionWrapper(expr string) string {
	s := strings.TrimSpace(expr)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		s = s[3 : len(s)-2]
		s = strings.TrimSpace(s)
	}
	return s
}

func ParseGateExpression(ifExpr, injectionSource string) GateConstraint {
	expr := strings.TrimSpace(ifExpr)
	if expr == "" {
		return GateConstraint{Solvable: true}
	}

	cleaned := stripExpressionWrapper(expr)
	node := parse(cleaned)
	if node == nil {
		return GateConstraint{Expression: expr, Solvable: true}
	}

	result := evaluate(node, injectionSource)
	return GateConstraint{
		Expression: expr,
		Solvable:   result.solvable,
		Triggers:   result.triggers,
		Unsolvable: result.unsolvable,
	}
}

func extractGateForFinding(
	workflows []models.GithubActionsWorkflow,
	findingPath, findingJob, findingStep string,
	injectionSources []string,
) GateConstraint {
	injSource := ""
	if len(injectionSources) > 0 {
		injSource = injectionSources[0]
	}

	var ifExprs []string
	for _, wf := range workflows {
		if !pathMatch(wf.Path, findingPath) {
			continue
		}
		for _, job := range wf.Jobs {
			if !jobMatch(job.ID, job.Name, findingJob) {
				continue
			}
			if job.If != "" {
				ifExprs = append(ifExprs, job.If)
			}
			for _, step := range job.Steps {
				if stepMatch(step.ID, step.Name, findingStep) && step.If != "" {
					ifExprs = append(ifExprs, step.If)
				}
			}
			break
		}
		break
	}

	if len(ifExprs) == 0 {
		return GateConstraint{Solvable: true}
	}

	var allTriggers []string
	for _, expr := range ifExprs {
		gc := ParseGateExpression(expr, injSource)
		if !gc.Solvable {
			return GateConstraint{
				Expression: expr,
				Solvable:   false,
				Unsolvable: gc.Unsolvable,
			}
		}
		allTriggers = append(allTriggers, gc.Triggers...)
	}

	rawExpr := ifExprs[0]
	if len(ifExprs) > 1 {
		rawExpr = strings.Join(ifExprs, " && ")
	}

	return GateConstraint{
		Expression: rawExpr,
		Solvable:   true,
		Triggers:   allTriggers,
	}
}

func pathMatch(wfPath, findingPath string) bool {
	return wfPath == findingPath
}

func jobMatch(jobID, jobName, findingJob string) bool {
	if findingJob == "" {
		return true
	}
	return strings.EqualFold(jobID, findingJob) ||
		strings.EqualFold(jobName, findingJob)
}

func stepMatch(stepID, stepName, findingStep string) bool {
	if findingStep == "" {
		return false
	}
	return strings.EqualFold(stepID, findingStep) ||
		strings.EqualFold(stepName, findingStep)
}
