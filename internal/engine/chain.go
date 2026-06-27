package engine

type AttackPhase int

const (
	PhaseSetup    AttackPhase = -1
	PhaseInfo     AttackPhase = 0
	PhaseAccess   AttackPhase = 1
	PhaseExec     AttackPhase = 2
	PhasePersist  AttackPhase = 3
	PhaseEscape   AttackPhase = 4
	PhaseLateral  AttackPhase = 5
	PhaseKubectl  AttackPhase = 6
	PhaseComplete AttackPhase = 99
)

var phaseNames = map[AttackPhase]string{
	PhaseSetup:    "setup",
	PhaseInfo:     "info",
	PhaseAccess:   "access",
	PhaseExec:     "exec",
	PhasePersist:  "persist",
	PhaseEscape:   "escape",
	PhaseLateral:  "lateral",
	PhaseKubectl:  "kubectl",
	PhaseComplete: "complete",
}

func (p AttackPhase) String() string {
	if name, ok := phaseNames[p]; ok {
		return name
	}
	return "unknown"
}

type PhaseTransition struct {
	From AttackPhase
	To   AttackPhase
}

var validTransitions = map[AttackPhase][]AttackPhase{
	PhaseSetup:   {PhaseInfo, PhaseAccess, PhaseKubectl},
	PhaseInfo:    {PhaseAccess, PhaseExec, PhaseKubectl, PhaseComplete},
	PhaseAccess:  {PhaseExec, PhasePersist, PhaseLateral, PhaseKubectl, PhaseComplete},
	PhaseExec:    {PhasePersist, PhaseEscape, PhaseLateral, PhaseKubectl, PhaseComplete},
	PhasePersist: {PhaseEscape, PhaseLateral, PhaseKubectl, PhaseComplete},
	PhaseEscape:  {PhasePersist, PhaseLateral, PhaseKubectl, PhaseComplete},
	PhaseLateral: {PhaseExec, PhasePersist, PhaseEscape, PhaseKubectl, PhaseComplete},
	PhaseKubectl: {PhaseInfo, PhaseAccess, PhaseExec, PhasePersist, PhaseComplete},
}

func IsValidTransition(from, to AttackPhase) bool {
	targets, ok := validTransitions[from]
	if !ok {
		return false
	}
	for _, t := range targets {
		if t == to {
			return true
		}
	}
	return false
}

func NextRecommendedPhases(current AttackPhase) []AttackPhase {
	return validTransitions[current]
}
