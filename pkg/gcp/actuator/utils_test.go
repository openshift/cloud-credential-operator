package actuator

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCalculateSliceDiff(t *testing.T) {
	tests := []struct {
		name            string
		original        []string
		new             []string
		expectedAdded   []string
		expectedRemoved []string
	}{
		{
			name:            "No Differences",
			original:        []string{"a", "b", "c", "d", "e", "f"},
			new:             []string{"a", "b", "c", "d", "e", "f"},
			expectedAdded:   []string{},
			expectedRemoved: []string{},
		},
		{
			name:            "Only Added",
			original:        []string{"a", "b", "c"},
			new:             []string{"a", "b", "c", "d", "e", "f"},
			expectedAdded:   []string{"d", "e", "f"},
			expectedRemoved: []string{},
		},
		{
			name:            "Only Removed",
			original:        []string{"a", "b", "c", "d", "e", "f"},
			new:             []string{"d", "e", "f"},
			expectedAdded:   []string{},
			expectedRemoved: []string{"a", "b", "c"},
		},
		{
			name:            "Added And Removed",
			original:        []string{"a", "b", "c", "d"},
			new:             []string{"c", "d", "e", "f"},
			expectedAdded:   []string{"e", "f"},
			expectedRemoved: []string{"a", "b"},
		},
		{
			name:            "Empty Original",
			original:        []string{},
			new:             []string{"a", "b", "c", "d", "e", "f"},
			expectedAdded:   []string{"a", "b", "c", "d", "e", "f"},
			expectedRemoved: []string{},
		},
		{
			name:            "Empty New",
			original:        []string{"a", "b", "c", "d", "e", "f"},
			new:             []string{},
			expectedAdded:   []string{},
			expectedRemoved: []string{"a", "b", "c", "d", "e", "f"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			added, removed := CalculateSliceDiff(test.original, test.new)
			assert.ElementsMatch(t, test.expectedAdded, added)
			assert.ElementsMatch(t, test.expectedRemoved, removed)
		})
	}
}
