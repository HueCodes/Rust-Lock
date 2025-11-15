package runner

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type Manager struct {
	mu      sync.RWMutex
	runners map[string]*Runner
}

type Runner struct {
	ID     string
	Status string
}

func NewManager() *Manager {
	return &Manager{
		runners: make(map[string]*Runner),
	}
}

func (m *Manager) Add() {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := generateID()
	m.runners[id] = &Runner{
		ID:     id,
		Status: "idle",
	}
	log.Printf("runner added: %s", id)
}

func (m *Manager) Remove() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id := range m.runners {
		delete(m.runners, id)
		log.Printf("runner removed: %s", id)
		return
	}
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.runners)
}

func generateID() string {
	return fmt.Sprintf("runner-%d", time.Now().UnixNano())
}
