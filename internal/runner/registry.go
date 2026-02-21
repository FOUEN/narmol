// Package runner provides a registry of external tools that narmol can invoke.
// Each tool registers a name and a Main() function.
package runner

import "fmt"

// Tool represents an external tool that narmol can run.
type Tool struct {
	Name        string
	Description string
	Main        func()
}

var registry = map[string]Tool{}

// Register adds a tool to the registry.
func Register(t Tool) {
	registry[t.Name] = t
}

// Get returns a tool by name.
func Get(name string) (Tool, error) {
	t, ok := registry[name]
	if !ok {
		return Tool{}, fmt.Errorf("unknown tool: %s", name)
	}
	return t, nil
}

// List returns all registered tools.
func List() []Tool {
	list := make([]Tool, 0, len(registry))
	for _, t := range registry {
		list = append(list, t)
	}
	return list
}
