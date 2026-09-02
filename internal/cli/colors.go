package cli

import (
	"github.com/fatih/color"
)

// Color helpers for job/target status
var (
	statusColor = func(s string) *color.Color {
		switch s {
		case "queued":
			return color.New(color.FgHiBlack)
		case "running":
			return color.New(color.FgYellow)
		case "done", "completed":
			return color.New(color.FgGreen)
		case "error":
			return color.New(color.FgRed).Add(color.Bold)
		default:
			return color.New(color.Reset)
		}
	}
	sourceColor = func(s string) *color.Color {
		if s == "watchdogs" {
			return color.New(color.FgCyan)
		}
		return color.New(color.Reset)
	}
)

func statusColorByConfidence(conf float64) *color.Color {
	if conf >= 0.7 {
		return color.New(color.FgHiRed)
	} else if conf >= 0.4 {
		return color.New(color.FgYellow)
	}
	return color.New(color.FgBlack)
}

func riskColor(risk string) *color.Color {
	switch risk {
	case "critical":
		return color.New(color.FgHiRed).Add(color.Bold)
	case "high":
		return color.New(color.FgRed)
	case "medium":
		return color.New(color.FgYellow)
	case "low":
		return color.New(color.FgGreen)
	default:
		return color.New(color.Reset)
	}
}

func severityColor(sev string) *color.Color {
	switch sev {
	case "critical":
		return color.New(color.FgHiRed).Add(color.Bold)
	case "high":
		return color.New(color.FgRed)
	case "medium":
		return color.New(color.FgYellow)
	case "low":
		return color.New(color.FgGreen)
	default:
		return color.New(color.Reset)
	}
}

func bold(s string) string {
	return color.New(color.Bold).Sprint(s)
}