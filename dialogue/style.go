package dialogue

import (
	"github.com/charmbracelet/lipgloss"
)

// These colors are from the gruvbox vim theme
// https://github.com/morhetz/gruvbox
var bg = lipgloss.AdaptiveColor{
	Light: "#fbf1c7",
	Dark:  "#282828",
}
var fg = lipgloss.AdaptiveColor{
	Light: "#3c3836",
	Dark:  "#ebdbb2",
}
var red = lipgloss.Color("#cc241d")
var green = lipgloss.Color("#98971a")
var yellow = lipgloss.Color("#d79921")
var blue = lipgloss.Color("#458588")
var purple = lipgloss.Color("#b16286")
var orange = lipgloss.Color("#d65d0e")

var baseStyle = lipgloss.NewStyle().
	Foreground(fg).
	Background(bg)

var delegateStyle = baseStyle.
	Foreground(blue).
	Bold(true)

var targetStyle = baseStyle.
	Foreground(purple).
	Bold(true)

var userStyle = baseStyle.
	Foreground(green).
	Italic(true)

var intentStyle = baseStyle.
	Foreground(red).
	Italic(true)

var timeStyle = baseStyle.
	Foreground(yellow)

var titleStyle = lipgloss.
	NewStyle().
	MarginLeft(2).
	MarginTop(1)

var itemStyle = lipgloss.
	NewStyle().
	PaddingLeft(4)

var selectedItemStyle = itemStyle.
	Foreground(orange)
