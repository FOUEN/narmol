package workflows

import (
	"fmt"

	"github.com/FOUEN/narmol/internal/scope"
)

// OutputOptions defines how workflow results should be output.
type OutputOptions struct {
	TextFile string
	JSONFile string
}

// Workflow defines the interface that all narmol workflows must implement.
type Workflow interface {
	// Name returns the workflow identifier.
	Name() string
	// Description returns a short description of what the workflow does.
	Description() string
	// Run executes the workflow for the given domain, enforcing scope rules.
	Run(domain string, s *scope.Scope, opts OutputOptions) error
}

// registry holds all registered workflows.
var registry = map[string]Workflow{}

// Register adds a workflow to the registry.
func Register(w Workflow) {
	registry[w.Name()] = w
}

// Get returns a workflow by name, or an error if not found.
func Get(name string) (Workflow, error) {
	w, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown workflow: %s", name)
	}
	return w, nil
}

// List returns all registered workflow names and descriptions.
func List() []Workflow {
	list := make([]Workflow, 0, len(registry))
	for _, w := range registry {
		list = append(list, w)
	}
	return list
}
