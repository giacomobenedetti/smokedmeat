// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

// Observer receives notifications of graph changes.
// Implementations must be thread-safe as notifications may come from
// concurrent goroutines.
type Observer interface {
	OnAssetAdded(asset Asset)
	OnAssetUpdated(asset Asset, oldState AssetState)
	OnRelationshipAdded(from, to string, rel Relationship)
	OnAssetRemoved(id string)
	OnRelationshipRemoved(from, to string)
}

// AddObserver registers an observer to receive change notifications.
func (p *Pantry) AddObserver(obs Observer) {
	p.obsMu.Lock()
	defer p.obsMu.Unlock()
	p.observers = append(p.observers, obs)
}

// RemoveObserver unregisters an observer.
func (p *Pantry) RemoveObserver(obs Observer) {
	p.obsMu.Lock()
	defer p.obsMu.Unlock()
	for i, o := range p.observers {
		if o == obs {
			p.observers = append(p.observers[:i], p.observers[i+1:]...)
			return
		}
	}
}

func (p *Pantry) notifyAssetAdded(asset Asset) {
	p.obsMu.RLock()
	observers := make([]Observer, len(p.observers))
	copy(observers, p.observers)
	p.obsMu.RUnlock()

	for _, obs := range observers {
		obs.OnAssetAdded(asset)
	}
}

func (p *Pantry) notifyAssetUpdated(asset Asset, oldState AssetState) {
	p.obsMu.RLock()
	observers := make([]Observer, len(p.observers))
	copy(observers, p.observers)
	p.obsMu.RUnlock()

	for _, obs := range observers {
		obs.OnAssetUpdated(asset, oldState)
	}
}

func (p *Pantry) notifyRelationshipAdded(from, to string, rel Relationship) {
	p.obsMu.RLock()
	observers := make([]Observer, len(p.observers))
	copy(observers, p.observers)
	p.obsMu.RUnlock()

	for _, obs := range observers {
		obs.OnRelationshipAdded(from, to, rel)
	}
}

func (p *Pantry) notifyAssetRemoved(id string) {
	p.obsMu.RLock()
	observers := make([]Observer, len(p.observers))
	copy(observers, p.observers)
	p.obsMu.RUnlock()

	for _, obs := range observers {
		obs.OnAssetRemoved(id)
	}
}

func (p *Pantry) notifyRelationshipRemoved(from, to string) {
	p.obsMu.RLock()
	observers := make([]Observer, len(p.observers))
	copy(observers, p.observers)
	p.obsMu.RUnlock()

	for _, obs := range observers {
		obs.OnRelationshipRemoved(from, to)
	}
}
