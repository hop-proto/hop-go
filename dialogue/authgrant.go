// Package dialogue contains utilities of getting user input
package dialogue

import (
	"errors"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
)

// AuthgrantModel implements tea.Model and contains all the data needed to render the authgrant dialogue
type AuthgrantModel struct {
	// TODO(hosono) deal with different grant types
	Intent      string
	DelegateSNI string
	TargetSNI   string
	TargetUser  string
	StartTime   time.Time
	EndTime     time.Time

	accept bool
}

var _ tea.Model = AuthgrantModel{}

func FromIntent(i *authgrants.Intent) AuthgrantModel {
	return AuthgrantModel{
		Intent:      i.AssociatedData.CommandGrantData.Cmd,
		DelegateSNI: i.DelegateCert.IDChunk.Blocks[0].String(),
		TargetSNI:   i.TargetSNI.String(),
		TargetUser:  i.TargetUsername,
		StartTime:   i.StartTime,
		EndTime:     i.ExpTime,
		accept:      false,
	}
}

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

// GetUserInputForAuthgrant displays the relevant information about an authgrant
// to the user. It returns nil if the user accepted the authgrand and and error otherwise.
func GetUserInputForAuthgrant(i authgrants.Intent, cert *certs.Certificate) error {
	mod := FromIntent(&i)
	m, err := tea.NewProgram(mod, tea.WithAltScreen()).Run()
	if err != nil {
		return err
	}
	if !m.(AuthgrantModel).accept {
		return errors.New("user denied perimission")
	}
	return nil
}

var _ authgrants.CheckIntentCallback = GetUserInputForAuthgrant

func GetAuthgrantInput(mod AuthgrantModel) (bool, error) {
	m, err := tea.NewProgram(mod, tea.WithAltScreen()).Run()

	// TODO(hosono) it would be great to make this infallible
	if err != nil {
		return false, err
	}

	return m.(AuthgrantModel).accept, nil
}
