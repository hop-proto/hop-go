// Package dialogue contains utilities of getting user input
package dialogue

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// AuthgrantModel implements tea.Model and contains all the data needed to render the authgrant dialogue
type AuthgrantModel struct {
	Intent      string
	DelegateSNI string
	TargetSNI   string
	TargetUser  string
	StartTime   time.Time
	EndTime     time.Time

	accept bool
}

var _ tea.Model = model{}

// Init implements the tea.Model interface
func (m AuthgrantModel) Init() tea.Cmd {
	return nil
}

// Update implements the tea.Model interface and runs the menu event loop
func (m AuthgrantModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m, tea.ClearScreen
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			m.accept = true
			return m, nil
		case "down", "j":
			m.accept = false
			return m, nil
		case "ctrl-c", "q":
			m.accept = false
			return m, tea.Quit
		case "enter":
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the UI with the data contained in model
func (m AuthgrantModel) View() string {
	delegateSNI := delegateStyle.Render(m.DelegateSNI)
	targetSNI := targetStyle.Render(m.TargetSNI)
	targetUser := userStyle.Render(m.TargetUser)
	intent := intentStyle.Render(m.Intent)
	startTime := timeStyle.Render(m.StartTime.In(time.Local).Format(time.UnixDate))
	endTime := timeStyle.Render(m.EndTime.In(time.Local).Format(time.UnixDate))

	text := fmt.Sprintf("Would you like to allow %s\n  to %s as %s on %s\n  from %s until %s?",
		delegateSNI,
		intent,
		targetUser,
		targetSNI,
		startTime,
		endTime,
	)

	title := titleStyle.Render(text)

	selectedPrefix := " > "
	unselectedPrefix := "   "

	var yes string
	var no string

	if m.accept {
		yes = selectedItemStyle.Render(selectedPrefix + "Yes")
		no = itemStyle.Render(unselectedPrefix + "No")
	} else {
		yes = itemStyle.Render(unselectedPrefix + "Yes")
		no = selectedItemStyle.Render(selectedPrefix + "No")
	}

	return lipgloss.JoinVertical(0, title, yes, no)
}

// GetAuthgrantInput displays the relevant information about an authgrant
// to the user. It returns a boolean indicating if they chose to accept the
// authgrant or not and an error is any occurred

var lock sync.Mutex

// Define a custom reader that ignores any input
type NoOpReader struct {
	r io.Reader
}

// Implement the Read method for NoOpReader
func (n *NoOpReader) Read(p []byte) (nBytes int, err error) {
	// Read data but do not actually store it anywhere (ignore it)
	return n.r.Read(p)
}

// Clear the input buffer by reading any remaining data in the input stream
func clearInputBuffer(r io.Reader) error {
	buffer := make([]byte, 1024) // Buffer size to read input
	for {
		// Try to read from the input
		n, err := r.Read(buffer)
		if n == 0 && err == io.EOF {
			// No more data to read, exit
			break
		}
		if err != nil && err != io.EOF {
			// Handle any errors encountered while reading
			return err
		}
		// If we read data (n > 0), just discard it
	}
	return nil
}

func GetAuthgrantInput(mod AuthgrantModel) (bool, error) {
	keyHandler := os.Stdin

	m, err := tea.NewProgram(mod, tea.WithInput(keyHandler)).Run()
	if err != nil {
		return false, err
	}

	err = clearInputBuffer(keyHandler)
	if err != nil {
		return false, err
	}

	return m.(AuthgrantModel).accept, nil
}
