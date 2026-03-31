// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPivotResult_MarshalRoundTrip(t *testing.T) {
	original := &PivotResult{
		Success:  true,
		Provider: "aws",
		Method:   "oidc",
		Credentials: map[string]string{
			"AssumedRole": "arn:aws:iam::123:role/deploy",
		},
		RawCredentials: map[string]string{
			"AWS_ACCESS_KEY_ID":     "ASIAEXAMPLE",
			"AWS_SECRET_ACCESS_KEY": "secret123",
			"AWS_SESSION_TOKEN":     "token456",
		},
		Resources: []CloudResource{
			{Type: "s3_bucket", Name: "my-bucket", Region: "us-east-1"},
			{Type: "identity", ID: "arn:aws:sts::123:assumed-role/deploy/session"},
		},
		Errors:   []string{},
		Duration: 250.5,
	}

	data, err := original.Marshal()
	require.NoError(t, err)

	restored, err := UnmarshalPivotResult(data)
	require.NoError(t, err)

	assert.Equal(t, original.Success, restored.Success)
	assert.Equal(t, original.Provider, restored.Provider)
	assert.Equal(t, original.Method, restored.Method)
	assert.Equal(t, original.Credentials["AssumedRole"], restored.Credentials["AssumedRole"])
	assert.Equal(t, original.RawCredentials["AWS_ACCESS_KEY_ID"], restored.RawCredentials["AWS_ACCESS_KEY_ID"])
	assert.Equal(t, original.RawCredentials["AWS_SECRET_ACCESS_KEY"], restored.RawCredentials["AWS_SECRET_ACCESS_KEY"])
	assert.Equal(t, original.RawCredentials["AWS_SESSION_TOKEN"], restored.RawCredentials["AWS_SESSION_TOKEN"])
	assert.Len(t, restored.Resources, 2)
	assert.Equal(t, "s3_bucket", restored.Resources[0].Type)
	assert.Equal(t, "us-east-1", restored.Resources[0].Region)
	assert.Equal(t, original.Duration, restored.Duration)
}

func TestUnmarshalPivotResult_InvalidJSON(t *testing.T) {
	_, err := UnmarshalPivotResult([]byte("not json"))
	assert.Error(t, err)
}

func TestUnmarshalPivotResult_EmptyProvider(t *testing.T) {
	result, err := UnmarshalPivotResult([]byte(`{"success":false}`))
	require.NoError(t, err)
	assert.Equal(t, "", result.Provider)
}
