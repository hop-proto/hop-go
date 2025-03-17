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
	Intent     authgrants.Intent
	TargetSNI  string
	TargetUser string
	StartTime  time.Time
	EndTime    time.Time

	accept bool
}

var _ tea.Model = AuthgrantModel{}

func FromIntent(i *authgrants.Intent) AuthgrantModel {
	return AuthgrantModel{
		Intent:     *i,
		TargetSNI:  i.TargetSNI.String(),
		TargetUser: i.TargetUsername,
		StartTime:  i.StartTime,
		EndTime:    i.ExpTime,
		accept:     false,
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
	delegateSNI := delegateStyle.Render(m.Intent.DelegateCert.IDChunk.Blocks[0].String())
	targetSNI := targetStyle.Render(m.TargetSNI)
	targetUser := userStyle.Render(m.TargetUser)
	startTime := timeStyle.Render(m.StartTime.In(time.Local).Format(time.UnixDate))
	endTime := timeStyle.Render(m.EndTime.In(time.Local).Format(time.UnixDate))

	var intentStr string
	switch m.Intent.GrantType {
	case authgrants.Shell:
		intentStr = intentStyle.Render("open a shell")
	case authgrants.Command:
		cmd := intentStyle.Render(m.Intent.AssociatedData.CommandGrantData.Cmd)
		intentStr = fmt.Sprintf("run the command '%s'", cmd)
	case authgrants.LocalPF, authgrants.RemotePF:
		intentStr = "TODO intent string for port forwarding"
	default:
		panic(fmt.Sprintf("unexpected authgrants.GrantType: %#v", m.Intent.GrantType))
	}

	text := fmt.Sprintf("Would you like to\n  allow %s\n  to %s\n  as %s\n  on %s\n  from %s\n  until %s?",
		delegateSNI,
		intentStr,
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
