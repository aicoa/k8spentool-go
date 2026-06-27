package util

import (
	"fmt"
	"strconv"
	"strings"
)

var capNames = map[int]string{
	0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 2: "CAP_DAC_READ_SEARCH",
	3: "CAP_FOWNER", 4: "CAP_FSETID", 5: "CAP_KILL",
	6: "CAP_SETGID", 7: "CAP_SETUID", 8: "CAP_SETPCAP",
	9: "CAP_NET_BIND_SERVICE", 10: "CAP_NET_BROADCAST",
	11: "CAP_NET_ADMIN", 12: "CAP_NET_RAW", 13: "CAP_IPC_LOCK",
	14: "CAP_IPC_OWNER", 15: "CAP_SYS_MODULE", 16: "CAP_SYS_RAWIO",
	17: "CAP_SYS_CHROOT", 18: "CAP_SYS_PTRACE", 19: "CAP_SYS_PACCT",
	20: "CAP_SYS_ADMIN", 21: "CAP_SYS_BOOT", 22: "CAP_SYS_NICE",
	23: "CAP_SYS_RESOURCE", 24: "CAP_SYS_TIME", 25: "CAP_SYS_TTY_CONFIG",
	26: "CAP_MKNOD", 27: "CAP_LEASE", 28: "CAP_AUDIT_WRITE",
	29: "CAP_AUDIT_CONTROL", 30: "CAP_SETFCAP", 31: "CAP_MAC_OVERRIDE",
	32: "CAP_MAC_ADMIN", 33: "CAP_SYSLOG", 34: "CAP_WAKE_ALARM",
	35: "CAP_BLOCK_SUSPEND", 36: "CAP_AUDIT_READ", 37: "CAP_PERFMON",
	38: "CAP_BPF", 39: "CAP_CHECKPOINT_RESTORE",
}

var dangerousCaps = map[int]string{
	20: "CAP_SYS_ADMIN - Full system administration",
	2: "CAP_DAC_READ_SEARCH - Can read any file on host",
	15: "CAP_SYS_MODULE - Can load kernel modules",
	18: "CAP_SYS_PTRACE - Can trace/inject any process",
	12: "CAP_NET_RAW - Can create raw sockets",
	11: "CAP_NET_ADMIN - Network configuration control",
	16: "CAP_SYS_RAWIO - Raw I/O port access",
	33: "CAP_SYSLOG - Can read kernel log",
	38: "CAP_BPF - Can load BPF programs",
}

type CapResult struct {
	Hex          string      `json:"hex"`
	CapMask      uint64      `json:"cap_mask"`
	AllCaps      []string    `json:"all_capabilities"`
	Dangerous    []CapDetail `json:"dangerous_capabilities"`
	HasAll       bool        `json:"has_all_caps"`
	IsPrivileged bool        `json:"is_privileged"`
	Warnings     []string    `json:"warnings"`
}

type CapDetail struct {
	Bit  int    `json:"bit"`
	Name string `json:"name"`
	Desc string `json:"description"`
}

func DecodeCapabilities(hex string) (*CapResult, error) {
	hex = strings.TrimSpace(hex)
	hex = strings.ReplaceAll(hex, "0x", "")
	hex = strings.ReplaceAll(hex, "0X", "")

	mask, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %s", hex)
	}

	result := &CapResult{Hex: hex, CapMask: mask}

	fullMask := uint64(0)
	for i := 0; i <= 39; i++ {
		fullMask |= (1 << i)
	}
	result.HasAll = (mask & fullMask) == fullMask

	for i := 0; i <= 39; i++ {
		if mask&(1<<i) != 0 {
			name, ok := capNames[i]
			if !ok {
				name = fmt.Sprintf("CAP_UNKNOWN_%d", i)
			}
			result.AllCaps = append(result.AllCaps, name)
			if desc, isDangerous := dangerousCaps[i]; isDangerous {
				result.Dangerous = append(result.Dangerous, CapDetail{Bit: i, Name: name, Desc: desc})
			}
		}
	}

	if len(result.Dangerous) > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Found %d dangerous capabilities!", len(result.Dangerous)))
	}
	if result.HasAll {
		result.Warnings = append(result.Warnings,
			"ALL capabilities enabled - container is effectively privileged!")
		result.IsPrivileged = true
	}
	if mask == 0 {
		result.Warnings = append(result.Warnings, "No capabilities found - may be running in restricted mode")
	}
	return result, nil
}
