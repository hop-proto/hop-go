// Package dialogue contains utilities of getting user input
package dialogue

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// model implements tea.Model and contains all the data needed to render the dialogue
// question is the line that will be rendered at the top of the dialogue window
// accept is true when the user selects "yes" and false when the user selects "no"
type model struct {
	question string
	accept   bool
}

var _ tea.Model = model{}

// The initial command that is run upon starting the model
func (m model) Init() tea.Cmd {
	return tea.EnterAltScreen
}

// The event loop for the dialogue menu. yes and no can be selected with
// up and down keys or with "j" and "k" as in vim. CTRL-C and "q" both exit the dialogue
// and select the "no" option. The enter key exits the dialogue with the selected option
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
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
func (m model) View() string {
	title := titleStyle.Render(m.question)

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

// GetUserInput enters the altscreen and displays a question to the user along with the
// options "yes" and "no". The user can select the options with the arrow keys or with
// "j" and "k" as in vim. If the user presses enter, this function returns.
// The boolean return value of this function is true is the user selected "yes"
// and false if the user selected "no". If the user presses "q" or CTRL-C,
// this function returns false regardless of what is currently selected.
// This means that the "no" option should be a safe default choice
// for whatever the user is selecting.
//
// Additionally, this function returns an error if an error occurs while running
// the dialogue. In that case, the boolean return value of this function is false
func GetUserInput(question string) (bool, error) {
	mod := model{
		accept:   false,
		question: question,
	}
	m, err := tea.NewProgram(mod).Run()

	// TODO(hosono) it would be great to make this infallible
	if err != nil {
		return false, err
	}

	return m.(model).accept, nil
}
