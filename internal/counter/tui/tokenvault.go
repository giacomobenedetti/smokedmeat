// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// TokenVault holds persisted tokens across sessions.
type TokenVault struct {
	Tokens    []VaultToken `yaml:"tokens"`
	UpdatedAt time.Time    `yaml:"updated_at"`
}

// VaultToken is the serializable form of CollectedSecret.
type VaultToken struct {
	Name        string    `yaml:"name"`
	Value       string    `yaml:"value"`
	Source      string    `yaml:"source"`
	Type        string    `yaml:"type,omitempty"`
	Scopes      []string  `yaml:"scopes,omitempty"`
	CollectedAt time.Time `yaml:"collected_at"`
	Repository  string    `yaml:"repository,omitempty"`
	Workflow    string    `yaml:"workflow,omitempty"`
	Job         string    `yaml:"job,omitempty"`
	AgentID     string    `yaml:"agent_id,omitempty"`
	PairedAppID string    `yaml:"paired_app_id,omitempty"`
}

// TokenVaultPath returns the path to the token vault file.
// Respects SMOKEDMEAT_CONFIG_DIR env var, defaults to ~/.smokedmeat.
func TokenVaultPath() string {
	if dir := os.Getenv("SMOKEDMEAT_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "tokens.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".smokedmeat", "tokens.yaml")
}

// LoadTokenVault loads the token vault from disk.
func LoadTokenVault() (*TokenVault, error) {
	path := TokenVaultPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &TokenVault{}, nil
		}
		return nil, err
	}

	var vault TokenVault
	if err := yaml.Unmarshal(data, &vault); err != nil {
		return nil, err
	}

	return &vault, nil
}

// SaveTokenVault saves the token vault to disk.
func SaveTokenVault(vault *TokenVault) error {
	path := TokenVaultPath()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	vault.UpdatedAt = time.Now()
	data, err := yaml.Marshal(vault)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

// ToCollectedSecrets converts vault tokens to CollectedSecret slice.
func (v *TokenVault) ToCollectedSecrets() []CollectedSecret {
	secrets := make([]CollectedSecret, 0, len(v.Tokens))
	indexByValue := make(map[string]int)
	indexByOrigin := make(map[string]int)
	for _, t := range v.Tokens {
		secret := CollectedSecret{
			Name:        t.Name,
			Value:       t.Value,
			Source:      t.Source,
			Type:        t.Type,
			Scopes:      t.Scopes,
			CollectedAt: t.CollectedAt,
			Repository:  t.Repository,
			Workflow:    t.Workflow,
			Job:         t.Job,
			AgentID:     t.AgentID,
			PairedAppID: t.PairedAppID,
		}
		valueKey := secret.Name + "\x00" + secret.Value
		if idx, ok := indexByValue[valueKey]; ok {
			mergeCollectedSecretMetadata(&secrets[idx], secret)
			continue
		}
		if originKey := lootOriginSlotKey(secret); originKey != "" {
			if idx, ok := indexByOrigin[originKey]; ok {
				if shouldReplaceCollectedSecret(secrets[idx], secret) {
					mergeCollectedSecretMetadata(&secret, secrets[idx])
					secrets[idx] = secret
					indexByValue[valueKey] = idx
				} else {
					mergeCollectedSecretMetadata(&secrets[idx], secret)
				}
				continue
			}
			indexByOrigin[originKey] = len(secrets)
		}
		indexByValue[valueKey] = len(secrets)
		secrets = append(secrets, secret)
	}
	return secrets
}

// FromCollectedSecrets creates a vault from CollectedSecret slice.
func FromCollectedSecrets(secrets []CollectedSecret) *TokenVault {
	tokens := make([]VaultToken, 0, len(secrets))
	indexByValue := make(map[string]int)
	indexByOrigin := make(map[string]int)
	for _, s := range secrets {
		if s.IsEphemeral() || s.ExpressMode {
			continue
		}
		valueKey := s.Name + "\x00" + s.Value
		if idx, ok := indexByValue[valueKey]; ok {
			existing := tokens[idx]
			merged := CollectedSecret{
				Name:        existing.Name,
				Value:       existing.Value,
				Source:      existing.Source,
				Type:        existing.Type,
				Scopes:      existing.Scopes,
				CollectedAt: existing.CollectedAt,
				Repository:  existing.Repository,
				Workflow:    existing.Workflow,
				Job:         existing.Job,
				AgentID:     existing.AgentID,
				PairedAppID: existing.PairedAppID,
			}
			mergeCollectedSecretMetadata(&merged, s)
			tokens[idx] = vaultTokenFromSecret(merged)
			continue
		}
		if originKey := lootOriginSlotKey(s); originKey != "" {
			if idx, ok := indexByOrigin[originKey]; ok {
				existing := tokens[idx]
				current := CollectedSecret{
					Name:        existing.Name,
					Value:       existing.Value,
					Source:      existing.Source,
					Type:        existing.Type,
					Scopes:      existing.Scopes,
					CollectedAt: existing.CollectedAt,
					Repository:  existing.Repository,
					Workflow:    existing.Workflow,
					Job:         existing.Job,
					AgentID:     existing.AgentID,
					PairedAppID: existing.PairedAppID,
				}
				if shouldReplaceCollectedSecret(current, s) {
					mergeCollectedSecretMetadata(&s, current)
					tokens[idx] = vaultTokenFromSecret(s)
					indexByValue[valueKey] = idx
				} else {
					mergeCollectedSecretMetadata(&current, s)
					tokens[idx] = vaultTokenFromSecret(current)
				}
				continue
			}
			indexByOrigin[originKey] = len(tokens)
		}
		indexByValue[valueKey] = len(tokens)
		tokens = append(tokens, vaultTokenFromSecret(s))
	}
	return &TokenVault{
		Tokens:    tokens,
		UpdatedAt: time.Now(),
	}
}

func vaultTokenFromSecret(s CollectedSecret) VaultToken {
	return VaultToken{
		Name:        s.Name,
		Value:       s.Value,
		Source:      s.Source,
		Type:        s.Type,
		Scopes:      s.Scopes,
		CollectedAt: s.CollectedAt,
		Repository:  s.Repository,
		Workflow:    s.Workflow,
		Job:         s.Job,
		AgentID:     s.AgentID,
		PairedAppID: s.PairedAppID,
	}
}

// TokenVaultSavedMsg is sent when the vault finishes saving.
type TokenVaultSavedMsg struct {
	Err error
}
