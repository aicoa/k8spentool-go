package evaluate

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

type RiskLevel int

const (
	RiskInfo     RiskLevel = 0
	RiskLow      RiskLevel = 1
	RiskMedium   RiskLevel = 2
	RiskHigh     RiskLevel = 3
	RiskCritical RiskLevel = 4
)

type Profile struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Checks      []Check `json:"checks"`
}

type Check struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	RiskLevel   RiskLevel              `json:"risk_level"`
	Executor    func(ctx context.Context, target *TargetInfo) (*CheckResult, error) `json:"-"`
}

type CheckResult struct {
	CheckID    string      `json:"check_id"`
	CheckName  string      `json:"check_name"`
	Category   string      `json:"category"`
	Success    bool        `json:"success"`
	RiskLevel  RiskLevel   `json:"risk_level"`
	Found      bool        `json:"found"`
	Summary    string      `json:"summary"`
	Details    interface{} `json:"details,omitempty"`
	Error      string      `json:"error,omitempty"`
}

type TargetInfo struct {
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Token       string            `json:"token,omitempty"`
	SkipTLS     bool              `json:"skip_tls"`
	TimeoutSec  int               `json:"timeout_sec"`
	OpenPorts   []int             `json:"open_ports,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

type EvaluateResult struct {
	ProfileID string        `json:"profile_id"`
	Target    *TargetInfo   `json:"target"`
	Results   []CheckResult `json:"results"`
	Summary   string        `json:"summary"`
	CriticalFindings []string `json:"critical_findings"`
}

type Engine struct {
	profiles map[string]*Profile
	mu       sync.RWMutex
}

func NewEngine() *Engine {
	e := &Engine{
		profiles: make(map[string]*Profile),
	}
	e.registerProfiles()
	return e
}

func (e *Engine) RegisterProfile(p *Profile) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.profiles[p.ID] = p
}

func (e *Engine) GetProfile(id string) (*Profile, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.profiles[id]
	return p, ok
}

func (e *Engine) ListProfiles() []*Profile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Profile, 0, len(e.profiles))
	for _, p := range e.profiles {
		result = append(result, p)
	}
	return result
}

func (e *Engine) Run(ctx context.Context, profileID string, target *TargetInfo) (*EvaluateResult, error) {
	profile, ok := e.GetProfile(profileID)
	if !ok {
		return nil, fmt.Errorf("profile %s not found", profileID)
	}

	result := &EvaluateResult{
		ProfileID: profileID,
		Target:    target,
		Results:   make([]CheckResult, 0, len(profile.Checks)),
	}

	for _, check := range profile.Checks {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		checkResult, err := check.Executor(ctx, target)
		if err != nil {
			checkResult = &CheckResult{
				CheckID:   check.ID,
				CheckName: check.Name,
				Category:  check.Category,
				Success:   false,
				Error:     err.Error(),
			}
		}
		result.Results = append(result.Results, *checkResult)

		if checkResult.RiskLevel >= RiskHigh && checkResult.Found {
			result.CriticalFindings = append(result.CriticalFindings,
				fmt.Sprintf("[%s] %s: %s", checkResult.Category, checkResult.CheckName, checkResult.Summary))
		}
	}

	result.Summary = fmt.Sprintf("Completed %d checks, %d critical findings",
		len(result.Results), len(result.CriticalFindings))
	return result, nil
}

func (e *Engine) RunToJSON(ctx context.Context, profileID string, target *TargetInfo) (string, error) {
	result, err := e.Run(ctx, profileID, target)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
