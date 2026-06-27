package ai

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/trymonoly/K8sPenTool-ng/internal/engine"
)

type SafetyConfig struct {
	RequireHumanApproval  bool     `json:"require_human_approval"`
	AllowedPhases         []string `json:"allowed_phases"`
	MaxConsecutiveSteps   int      `json:"max_consecutive_steps"`
	DenyDestructive       bool     `json:"deny_destructive"`
	AllowedTargets        []string `json:"allowed_targets"`
	BlockedTargets        []string `json:"blocked_targets"`
	MaxRiskLevel          engine.RiskLevel `json:"max_risk_level"`
}

func DefaultSafetyConfig() *SafetyConfig {
	return &SafetyConfig{
		RequireHumanApproval: true,
		AllowedPhases:        []string{"info", "access", "exec", "persist", "escape", "lateral", "kubectl"},
		MaxConsecutiveSteps:  20,
		DenyDestructive:      false,
		MaxRiskLevel:         engine.RiskCritical,
	}
}

// Destructive tool names that actually modify the cluster and should trigger human approval.
// We use exact tool name matching to avoid blocking read-only tools that happen to
// contain words like "exec" or "escape" in their name (e.g. exec_list_pods, escape_check).
var destructiveToolNames = map[string]bool{
	"persist_create_admin_sa": true,
	"persist_cronjob":         true,
	"escape_privileged":       true,
	"kubectl_exec":            true, // can run arbitrary kubectl commands including delete/apply
}

// toolRiskLevels maps each tool to its actual risk level, used by the safety gate.
var toolRiskLevels = map[string]engine.RiskLevel{
	"info_port_scan":           engine.RiskInfo,
	"info_run_evaluate":        engine.RiskInfo,
	"access_apiserver":         engine.RiskLow,
	"access_kubelet":           engine.RiskMedium,
	"access_etcd_check":        engine.RiskMedium,
	"access_dashboard":         engine.RiskMedium,
	"exec_list_pods":           engine.RiskLow,
	"exec_command":             engine.RiskMedium,
	"lateral_list_secrets":     engine.RiskMedium,
	"lateral_view_secret":      engine.RiskHigh,
	"lateral_discover_services": engine.RiskLow,
	"persist_create_admin_sa":  engine.RiskCritical,
	"persist_cronjob":          engine.RiskCritical,
	"escape_check":             engine.RiskInfo,
	"escape_privileged":        engine.RiskCritical,
	"kubectl_exec":             engine.RiskHigh,
}

// GetToolRiskLevel returns the risk level for a tool, defaulting to RiskMedium.
func GetToolRiskLevel(toolName string) engine.RiskLevel {
	if rl, ok := toolRiskLevels[toolName]; ok {
		return rl
	}
	return engine.RiskMedium
}

type GuardResult struct {
	Allowed      bool   `json:"allowed"`
	Reason       string `json:"reason"`
	RiskLevel    engine.RiskLevel `json:"risk_level"`
	NeedApproval bool   `json:"need_approval"`
}

// CheckTarget validates if the target is allowed
func (c *SafetyConfig) CheckTarget(target *engine.Target) *GuardResult {
	if len(c.BlockedTargets) > 0 {
		for _, blocked := range c.BlockedTargets {
			if matchHost(target.Host, blocked) {
				return &GuardResult{
					Allowed: false,
					Reason:  fmt.Sprintf("target %s is in blocklist", target.Host),
				}
			}
		}
	}

	if len(c.AllowedTargets) > 0 {
		allowed := false
		for _, a := range c.AllowedTargets {
			if matchHost(target.Host, a) {
				allowed = true
				break
			}
		}
		if !allowed {
			return &GuardResult{
				Allowed: false,
				Reason:  fmt.Sprintf("target %s is not in allowlist", target.Host),
			}
		}
	}

	return &GuardResult{Allowed: true}
}

// CheckPhase validates if the phase transition is allowed
func (c *SafetyConfig) CheckPhase(currentPhase, nextPhase engine.AttackPhase) *GuardResult {
	phaseName := nextPhase.String()
	for _, allowed := range c.AllowedPhases {
		if allowed == phaseName {
			if !engine.IsValidTransition(currentPhase, nextPhase) {
				return &GuardResult{
					Allowed: false,
					Reason:  fmt.Sprintf("invalid phase transition: %s -> %s", currentPhase, nextPhase),
				}
			}
			return &GuardResult{Allowed: true}
		}
	}
	return &GuardResult{
		Allowed: false,
		Reason:  fmt.Sprintf("phase %s is not in allowed phases", phaseName),
	}
}

// CheckAction validates if a specific action is allowed
func (c *SafetyConfig) CheckAction(toolName string, action string, riskLevel engine.RiskLevel) *GuardResult {
	isDestructive := isDestructiveAction(toolName)

	if c.DenyDestructive && isDestructive {
		return &GuardResult{
			Allowed:   false,
			Reason:    "destructive actions are disabled",
			RiskLevel: riskLevel,
		}
	}

	if riskLevel > c.MaxRiskLevel {
		return &GuardResult{
			Allowed:   false,
			Reason:    fmt.Sprintf("risk level %s exceeds maximum %s", riskLevel, c.MaxRiskLevel),
			RiskLevel: riskLevel,
		}
	}

	if c.RequireHumanApproval && isDestructive {
		return &GuardResult{
			Allowed:      true,
			NeedApproval: true,
			Reason:       "destructive action requires human approval",
			RiskLevel:    riskLevel,
		}
	}

	return &GuardResult{Allowed: true, RiskLevel: riskLevel}
}

func isDestructiveAction(toolName string) bool {
	return destructiveToolNames[toolName]
}

func matchHost(host, pattern string) bool {
	if host == pattern {
		return true
	}
	re, err := regexp.Compile(strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*"))
	if err != nil {
		return false
	}
	return re.MatchString(host)
}
