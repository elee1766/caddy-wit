// Package caddyfile provides a Dispenser over the Caddyfile tokens that a
// guest receives in its config.unmarshal-caddyfile export. It mirrors the
// API and semantics of caddy's caddyconfig/caddyfile.Dispenser (caddy
// v2.11.4) so guest plugin code reads like native Caddy plugin code.
//
// The package is plain Go with no wasm dependencies, so it builds (and its
// tests run) on any platform.
package caddyfile

import (
	"errors"
	"fmt"
	"strings"
)

// Token is a single Caddyfile token as delivered over the
// caddy:plugin/config.token record. Quoted reports whether the token was
// enclosed in quotes (double quotes, backticks, or heredoc) in the
// Caddyfile; it lets the Dispenser distinguish a literal "{" argument from
// a block-opening brace.
type Token struct {
	File   string
	Line   int
	Text   string
	Quoted bool
}

// numLineBreaks counts how many line breaks are in the token text.
// (Unlike native caddy we cannot add the two extra heredoc line breaks,
// because the wire format only carries a quoted bool, not the quote kind.)
func (t Token) numLineBreaks() int {
	return strings.Count(t.Text, "\n")
}

// Dispenser is a type that dispenses tokens, similarly to a lexer,
// except that it can do so with some notion of structure. An empty
// Dispenser is invalid; call NewDispenser to make a proper instance.
type Dispenser struct {
	tokens  []Token
	cursor  int
	nesting int
}

// NewDispenser returns a Dispenser filled with the given tokens.
func NewDispenser(tokens []Token) *Dispenser {
	return &Dispenser{
		tokens: tokens,
		cursor: -1,
	}
}

// Next loads the next token. Returns true if a token
// was loaded; false otherwise. If false, all tokens
// have been consumed.
func (d *Dispenser) Next() bool {
	if d.cursor < len(d.tokens)-1 {
		d.cursor++
		return true
	}
	return false
}

// Prev moves to the previous token. It does the inverse
// of Next(), except this function may decrement the cursor
// to -1 so that the next call to Next() points to the
// first token; this allows dispensing to "start over". This
// method returns true if the cursor ends up pointing to a
// valid token.
func (d *Dispenser) Prev() bool {
	if d.cursor > -1 {
		d.cursor--
		return d.cursor > -1
	}
	return false
}

// NextArg loads the next token if it is on the same
// line and if it is not a block opening (open curly
// brace). Returns true if an argument token was
// loaded; false otherwise. If false, all tokens on
// the line have been consumed except for potentially
// a block opening. A quoted "{" is a literal argument,
// not a block opening.
func (d *Dispenser) NextArg() bool {
	if !d.nextOnSameLine() {
		return false
	}
	if d.isOpenCurlyBrace() {
		// roll back; a block opening is not an argument
		d.cursor--
		return false
	}
	return true
}

// nextOnSameLine advances the cursor if the next
// token is on the same line of the same file.
func (d *Dispenser) nextOnSameLine() bool {
	if d.cursor < 0 {
		d.cursor++
		return true
	}
	if d.cursor >= len(d.tokens)-1 {
		return false
	}
	curr := d.tokens[d.cursor]
	next := d.tokens[d.cursor+1]
	if !isNextOnNewLine(curr, next) {
		d.cursor++
		return true
	}
	return false
}

// NextLine loads the next token only if it is not on the same
// line as the current token, and returns true if a token was
// loaded; false otherwise. If false, there is not another token
// or it is on the same line.
func (d *Dispenser) NextLine() bool {
	if d.cursor < 0 {
		d.cursor++
		return true
	}
	if d.cursor >= len(d.tokens)-1 {
		return false
	}
	curr := d.tokens[d.cursor]
	next := d.tokens[d.cursor+1]
	if isNextOnNewLine(curr, next) {
		d.cursor++
		return true
	}
	return false
}

// NextBlock can be used as the condition of a for loop
// to load the next token as long as it opens a block or
// is already in a block nested more than initialNestingLevel.
// In other words, a loop over NextBlock() will iterate
// all tokens in the block assuming the next token is an
// open curly brace, until the matching closing brace.
// The open and closing brace tokens for the outer-most
// block will be consumed internally and omitted from
// the iteration.
//
// Proper use of this method looks like this:
//
//	for nesting := d.Nesting(); d.NextBlock(nesting); {
//	}
//
// However, in simple cases where it is known that the
// Dispenser is new and has not already traversed state
// by a loop over NextBlock(), this will do:
//
//	for d.NextBlock(0) {
//	}
//
// As with other token parsing logic, a loop over
// NextBlock() should be contained within a loop over
// Next(), as it is usually prudent to skip the initial
// token.
func (d *Dispenser) NextBlock(initialNestingLevel int) bool {
	if d.nesting > initialNestingLevel {
		if !d.Next() {
			return false // should be EOF error
		}
		if d.isCloseCurlyBrace() && !d.nextOnSameLine() {
			d.nesting--
		} else if d.isOpenCurlyBrace() && !d.nextOnSameLine() {
			d.nesting++
		}
		return d.nesting > initialNestingLevel
	}
	if !d.nextOnSameLine() { // block must open on same line
		return false
	}
	if !d.isOpenCurlyBrace() {
		d.cursor-- // roll back if not opening brace
		return false
	}
	d.Next() // consume open curly brace
	if d.isCloseCurlyBrace() {
		return false // open and then closed right away
	}
	d.nesting++
	return true
}

// isOpenCurlyBrace reports whether the current token is an unquoted "{".
// A quoted "{" is a literal string argument, never a block opening.
func (d *Dispenser) isOpenCurlyBrace() bool {
	return d.Val() == "{" && !d.quoted()
}

// isCloseCurlyBrace reports whether the current token is an unquoted "}".
func (d *Dispenser) isCloseCurlyBrace() bool {
	return d.Val() == "}" && !d.quoted()
}

// quoted reports whether the current token was quoted in the Caddyfile.
func (d *Dispenser) quoted() bool {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return false
	}
	return d.tokens[d.cursor].Quoted
}

// Nesting returns the current nesting level. Necessary
// if using NextBlock()
func (d *Dispenser) Nesting() int {
	return d.nesting
}

// Val gets the text of the current token. If there is no token
// loaded, it returns empty string.
func (d *Dispenser) Val() string {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return ""
	}
	return d.tokens[d.cursor].Text
}

// Line gets the line number of the current token.
// If there is no token loaded, it returns 0.
func (d *Dispenser) Line() int {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return 0
	}
	return d.tokens[d.cursor].Line
}

// File gets the filename where the current token originated.
func (d *Dispenser) File() string {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return ""
	}
	return d.tokens[d.cursor].File
}

// Args is a convenience function that loads the next arguments
// (tokens on the same line) into an arbitrary number of strings
// pointed to in targets. If there are not enough argument tokens
// available to fill targets, false is returned and the remaining
// targets are left unchanged. If all the targets are filled,
// then true is returned.
func (d *Dispenser) Args(targets ...*string) bool {
	for i := range targets {
		if !d.NextArg() {
			return false
		}
		*targets[i] = d.Val()
	}
	return true
}

// AllArgs is like Args, but if there are more argument tokens
// available than there are targets, false is returned. The
// number of available argument tokens must match the number of
// targets exactly to return true.
func (d *Dispenser) AllArgs(targets ...*string) bool {
	if !d.Args(targets...) {
		return false
	}
	if d.NextArg() {
		d.Prev()
		return false
	}
	return true
}

// CountRemainingArgs counts the amount of remaining arguments
// (tokens on the same line) without consuming the tokens.
func (d *Dispenser) CountRemainingArgs() int {
	count := 0
	for d.NextArg() {
		count++
	}
	for i := 0; i < count; i++ {
		d.Prev()
	}
	return count
}

// RemainingArgs loads any more arguments (tokens on the same line)
// into a slice of strings and returns them. Open curly brace tokens
// also indicate the end of arguments, and the curly brace is not
// included in the return value nor is it loaded.
func (d *Dispenser) RemainingArgs() []string {
	var args []string
	for d.NextArg() {
		args = append(args, d.Val())
	}
	return args
}

// Reset sets d's cursor to the beginning, as
// if this was a new and unused dispenser.
func (d *Dispenser) Reset() {
	d.cursor = -1
	d.nesting = 0
}

// ArgErr returns an argument error, meaning that another
// argument was expected but not found. In other words,
// a line break or open curly brace was encountered instead of
// an argument.
func (d *Dispenser) ArgErr() error {
	if d.Val() == "{" {
		return d.Err("unexpected token '{', expecting argument")
	}
	return d.Errf("wrong argument count or unexpected line ending after '%s'", d.Val())
}

// SyntaxErr creates a generic syntax error which explains what was
// found and what was expected.
func (d *Dispenser) SyntaxErr(expected string) error {
	msg := fmt.Sprintf("syntax error: unexpected token '%s', expecting '%s', at %s:%d", d.Val(), expected, d.File(), d.Line())
	return errors.New(msg)
}

// EOFErr returns an error indicating that the dispenser reached
// the end of the input when searching for the next token.
func (d *Dispenser) EOFErr() error {
	return d.Errf("unexpected EOF")
}

// Err generates a custom parse-time error with a message of msg.
func (d *Dispenser) Err(msg string) error {
	return d.WrapErr(errors.New(msg))
}

// Errf is like Err, but for formatted error messages
func (d *Dispenser) Errf(format string, args ...any) error {
	return d.WrapErr(fmt.Errorf(format, args...))
}

// WrapErr takes an existing error and adds the Caddyfile file and line number.
func (d *Dispenser) WrapErr(err error) error {
	return fmt.Errorf("%w, at %s:%d", err, d.File(), d.Line())
}

// isNextOnNewLine determines whether t2 is on a different line (higher
// line number) than t1, accounting for line breaks inside t1's text.
func isNextOnNewLine(t1, t2 Token) bool {
	// If the second token is from a different file,
	// we can assume it's from a different line.
	if t1.File != t2.File {
		return true
	}
	// If the first token (incl line breaks) ends
	// on a line earlier than the next token,
	// then the second token is on a new line.
	return t1.Line+t1.numLineBreaks() < t2.Line
}
