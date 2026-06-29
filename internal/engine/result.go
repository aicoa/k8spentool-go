package engine

import "time"

type RiskLevel int

const (
	RiskInfo     RiskLevel = 0
	RiskLow      RiskLevel = 1
	RiskMedium   RiskLevel = 2
	RiskHigh     RiskLevel = 3
	RiskCritical RiskLevel = 4
)

func (r RiskLevel) String() string {
	switch r {
	case RiskInfo:
		return "info"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

type StepResult struct {
	ID        string      `json:"id"`
	Phase     AttackPhase `json:"phase"`
	Tool      string      `json:"tool"`
	Action    string      `json:"action"`
	Source    string      `json:"source,omitempty"`
	Success   bool        `json:"success"`
	Summary   string      `json:"summary"`
	Data      interface{} `json:"data,omitempty"`
	Output    string      `json:"output,omitempty"`
	RiskLevel RiskLevel   `json:"risk_level"`
	Duration  int64       `json:"duration_ms"`
	Timestamp time.Time   `json:"timestamp"`
	Error     string      `json:"error,omitempty"`
}

type AttackPlan struct {
	ID          string     `json:"id"`
	TargetID    string     `json:"target_id"`
	Objective   string     `json:"objective"`
	Steps       []PlanStep `json:"steps"`
	CurrentStep int        `json:"current_step"`
	Status      string     `json:"status"` // "planning", "running", "paused", "completed", "failed"
	CreatedAt   time.Time  `json:"created_at"`
}

type PlanStep struct {
	Phase       AttackPhase            `json:"phase"`
	Tool        string                 `json:"tool"`
	Action      string                 `json:"action"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Status      string                 `json:"status"` // "pending", "running", "completed", "skipped", "failed"
	Result      *StepResult            `json:"result,omitempty"`
}

type ExploitResult struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Summary   string      `json:"summary"`
	RiskLevel RiskLevel   `json:"risk_level"`
	Evidence  []string    `json:"evidence,omitempty"`
	Error     string      `json:"error,omitempty"`
}
