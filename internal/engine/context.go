package engine

import (
	"sync"
	"time"
)

type AuthType string

const (
	AuthNone       AuthType = "none"
	AuthToken      AuthType = "token"
	AuthCert       AuthType = "cert"
	AuthKubeconfig AuthType = "kubeconfig"
	AuthUserPass   AuthType = "userpass"
)

type Target struct {
	ID         string    `json:"id"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Token      string    `json:"token,omitempty"`
	AuthType   AuthType  `json:"auth_type"`
	SkipTLS    bool      `json:"skip_tls"`
	TimeoutSec int       `json:"timeout_sec"`
	Kubeconfig string    `json:"kubeconfig,omitempty"`
	Username   string    `json:"username,omitempty"`
	Password   string    `json:"password,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type SessionState struct {
	mu             sync.RWMutex
	Target         *Target                      `json:"target"`
	CurrentPhase   AttackPhase                  `json:"current_phase"`
	CompletedSteps []StepResult                 `json:"completed_steps"`
	PhaseResults   map[AttackPhase][]StepResult `json:"phase_results"`
	StartTime      time.Time                    `json:"start_time"`
	IsRunning      bool                         `json:"is_running"`
}

func NewSessionState(target *Target) *SessionState {
	return &SessionState{
		Target:       target,
		CurrentPhase: PhaseSetup,
		PhaseResults: make(map[AttackPhase][]StepResult),
		StartTime:    time.Now(),
	}
}

func (s *SessionState) TransitionTo(phase AttackPhase) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !IsValidTransition(s.CurrentPhase, phase) {
		return false
	}
	s.CurrentPhase = phase
	return true
}

func (s *SessionState) AddResult(result StepResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CompletedSteps = append(s.CompletedSteps, result)
	s.PhaseResults[s.CurrentPhase] = append(s.PhaseResults[s.CurrentPhase], result)
}

func (s *SessionState) AddPhaseResult(result StepResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CompletedSteps = append(s.CompletedSteps, result)
	s.PhaseResults[result.Phase] = append(s.PhaseResults[result.Phase], result)
	if result.Phase == s.CurrentPhase || IsValidTransition(s.CurrentPhase, result.Phase) {
		s.CurrentPhase = result.Phase
	}
}

func (s *SessionState) GetPhase() AttackPhase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentPhase
}

func (s *SessionState) GetResults() []StepResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]StepResult, len(s.CompletedSteps))
	copy(results, s.CompletedSteps)
	return results
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Phase     string    `json:"phase,omitempty"`
}
