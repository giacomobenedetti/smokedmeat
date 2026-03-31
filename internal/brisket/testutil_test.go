// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

type mockTransport struct {
	handler func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.handler(req)
}

func newMockClient(handler func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{Transport: &mockTransport{handler: handler}}
}

func jsonResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func xmlResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     http.Header{"Content-Type": []string{"text/xml"}},
	}
}

func emptyResponse(statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Header:     http.Header{},
	}
}
