package caddyfile

import (
	"reflect"
	"strings"
	"testing"
)

// lex builds a token stream from a Caddyfile-like snippet for tests: each
// line is split on whitespace, and a field wrapped in double quotes becomes
// a Quoted token with the quotes stripped (matching what caddy's lexer
// produces). It is intentionally simple; no escapes or multi-word quotes.
func lex(input string) []Token {
	var tokens []Token
	for i, line := range strings.Split(input, "\n") {
		for _, f := range strings.Fields(line) {
			tok := Token{File: "Testfile", Line: i + 1, Text: f}
			if len(f) >= 2 && strings.HasPrefix(f, `"`) && strings.HasSuffix(f, `"`) {
				tok.Text = f[1 : len(f)-1]
				tok.Quoted = true
			}
			tokens = append(tokens, tok)
		}
	}
	return tokens
}

func testDispenser(input string) *Dispenser {
	return NewDispenser(lex(input))
}

func TestDispenserValNext(t *testing.T) {
	input := `host:port
dir1 arg1
dir2 arg2 arg3
dir3`
	d := testDispenser(input)

	if val := d.Val(); val != "" {
		t.Fatalf("Val(): should be empty before Next(); got %q", val)
	}

	for i, want := range []string{"host:port", "dir1", "arg1", "dir2", "arg2", "arg3", "dir3"} {
		if !d.Next() {
			t.Fatalf("Next(): step %d: expected true", i)
		}
		if got := d.Val(); got != want {
			t.Errorf("Val(): step %d: got %q, want %q", i, got, want)
		}
	}
	// Past EOF: Next is false and Val keeps the last token (native behavior).
	if d.Next() {
		t.Error("Next(): expected false at EOF")
	}
	if got := d.Val(); got != "dir3" {
		t.Errorf("Val() after EOF: got %q, want dir3", got)
	}
}

func TestDispenserNextArg(t *testing.T) {
	input := `dir1 arg1
dir2 arg2 arg3
dir3`
	d := testDispenser(input)

	assertNext := func(wantVal string) {
		t.Helper()
		if !d.Next() {
			t.Fatalf("Next(): expected true (want val %q)", wantVal)
		}
		if got := d.Val(); got != wantVal {
			t.Errorf("Val(): got %q, want %q", got, wantVal)
		}
	}
	assertNextArg := func(wantVal string, more bool) {
		t.Helper()
		if !d.NextArg() {
			t.Fatalf("NextArg(): expected true (want val %q)", wantVal)
		}
		if got := d.Val(); got != wantVal {
			t.Errorf("Val(): got %q, want %q", got, wantVal)
		}
		if !more {
			if d.NextArg() {
				t.Fatalf("NextArg(): expected false after %q, got true (val %q)", wantVal, d.Val())
			}
		}
	}

	assertNext("dir1")
	assertNextArg("arg1", false)
	assertNext("dir2")
	assertNextArg("arg2", true)
	assertNextArg("arg3", false)
	assertNext("dir3")
	if d.Next() {
		t.Error("Next(): expected false at EOF")
	}
}

func TestDispenserNextLine(t *testing.T) {
	input := `host:port
dir1 arg1`
	d := testDispenser(input)

	if !d.NextLine() {
		t.Fatal("NextLine(): expected true for first token")
	}
	if d.Val() != "host:port" {
		t.Errorf("Val() = %q, want host:port", d.Val())
	}
	if !d.NextLine() {
		t.Fatal("NextLine(): expected true (next token is on a new line)")
	}
	if d.Val() != "dir1" {
		t.Errorf("Val() = %q, want dir1", d.Val())
	}
	if d.NextLine() {
		t.Errorf("NextLine(): expected false (arg1 is on the same line), got val %q", d.Val())
	}
}

func TestDispenserNextBlock(t *testing.T) {
	input := `foobar1 {
sub1 arg1
sub2
}
foobar2 {
}`
	d := testDispenser(input)

	assertNextBlock := func(shouldLoad bool, wantNesting int) {
		t.Helper()
		if got := d.NextBlock(0); got != shouldLoad {
			t.Fatalf("NextBlock(): got %v, want %v (val %q)", got, shouldLoad, d.Val())
		}
		if d.Nesting() != wantNesting {
			t.Errorf("Nesting() = %d, want %d", d.Nesting(), wantNesting)
		}
	}

	assertNextBlock(false, 0) // no block is open yet; cursor at -1 advances to foobar1 then rolls back
	d.Next()                  // foobar1
	assertNextBlock(true, 1)  // enters block, loads sub1
	if d.Val() != "sub1" {
		t.Errorf("Val() = %q, want sub1", d.Val())
	}
	assertNextBlock(true, 1) // arg1
	assertNextBlock(true, 1) // sub2
	assertNextBlock(false, 0)
	d.Next()                  // foobar2
	assertNextBlock(false, 0) // empty block is not entered
}

func TestDispenserNestedBlocks(t *testing.T) {
	input := `dir {
inner {
x y
}
z
}`
	d := testDispenser(input)

	d.Next() // dir
	var got []string
	for outer := d.Nesting(); d.NextBlock(outer); {
		if d.Val() != "inner" {
			got = append(got, d.Val())
			continue
		}
		// nested block
		for inner := d.Nesting(); d.NextBlock(inner); {
			got = append(got, "inner."+d.Val())
		}
	}
	want := []string{"inner.x", "inner.y", "z"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nested walk = %v, want %v", got, want)
	}
	if d.Nesting() != 0 {
		t.Errorf("Nesting() = %d after full walk, want 0", d.Nesting())
	}
}

// TestDispenserQuotedBrace is the reason the quoted field exists: a quoted
// "{" is a literal argument and must not open a block, while an unquoted
// "{" does open one.
func TestDispenserQuotedBrace(t *testing.T) {
	t.Run("quoted brace is an argument", func(t *testing.T) {
		d := NewDispenser([]Token{
			{File: "Caddyfile", Line: 1, Text: "dir"},
			{File: "Caddyfile", Line: 1, Text: "{", Quoted: true},
			{File: "Caddyfile", Line: 1, Text: "tail"},
		})
		d.Next() // dir
		if !d.NextArg() {
			t.Fatal("NextArg(): quoted { must be loaded as an argument")
		}
		if d.Val() != "{" {
			t.Errorf("Val() = %q, want {", d.Val())
		}
		if !d.NextArg() || d.Val() != "tail" {
			t.Errorf("NextArg(): expected tail after literal brace, got %q", d.Val())
		}
	})

	t.Run("quoted brace does not open a block", func(t *testing.T) {
		d := NewDispenser([]Token{
			{File: "Caddyfile", Line: 1, Text: "dir"},
			{File: "Caddyfile", Line: 1, Text: "{", Quoted: true},
		})
		d.Next() // dir
		if d.NextBlock(0) {
			t.Fatal("NextBlock(): quoted { must not open a block")
		}
		// The brace remains available as an argument.
		if !d.NextArg() || d.Val() != "{" {
			t.Errorf("NextArg() after NextBlock: got val %q, want literal {", d.Val())
		}
	})

	t.Run("unquoted brace opens a block", func(t *testing.T) {
		d := NewDispenser([]Token{
			{File: "Caddyfile", Line: 1, Text: "dir"},
			{File: "Caddyfile", Line: 1, Text: "{"},
			{File: "Caddyfile", Line: 2, Text: "sub"},
			{File: "Caddyfile", Line: 3, Text: "}"},
		})
		d.Next() // dir
		if d.NextArg() {
			t.Fatalf("NextArg(): unquoted { is not an argument (val %q)", d.Val())
		}
		if !d.NextBlock(0) {
			t.Fatal("NextBlock(): unquoted { must open a block")
		}
		if d.Val() != "sub" {
			t.Errorf("Val() = %q, want sub", d.Val())
		}
	})

	t.Run("quoted RemainingArgs includes literal braces", func(t *testing.T) {
		d := testDispenser(`dir a "{" b "}" c`)
		d.Next()
		got := d.RemainingArgs()
		want := []string{"a", "{", "b", "}", "c"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("RemainingArgs() = %v, want %v", got, want)
		}
	})
}

func TestDispenserArgsAllArgs(t *testing.T) {
	input := `dir a b c
dir2 x`
	d := testDispenser(input)

	d.Next() // dir
	var s1, s2 string
	if !d.Args(&s1, &s2) {
		t.Fatal("Args(): expected true for two of three args")
	}
	if s1 != "a" || s2 != "b" {
		t.Errorf("Args() loaded %q, %q; want a, b", s1, s2)
	}
	var s3, s4 string
	if d.Args(&s3, &s4) {
		t.Error("Args(): expected false when not enough args remain")
	}
	if s3 != "c" {
		t.Errorf("Args(): partial fill got %q, want c", s3)
	}
	if s4 != "" {
		t.Errorf("Args(): unfilled target modified to %q", s4)
	}

	d.Reset()
	d.Next() // dir
	var t1, t2 string
	if d.AllArgs(&t1, &t2) {
		t.Error("AllArgs(): expected false with three args for two targets")
	}
	d.Reset()
	d.Next() // dir
	var u1, u2, u3 string
	if !d.AllArgs(&u1, &u2, &u3) {
		t.Fatal("AllArgs(): expected true with exact target count")
	}
	if u1 != "a" || u2 != "b" || u3 != "c" {
		t.Errorf("AllArgs() = %q %q %q, want a b c", u1, u2, u3)
	}
}

func TestDispenserRemainingArgs(t *testing.T) {
	input := `dir1 arg1 arg2 arg3
dir2 arg4 arg5
dir3 arg6 {
sub
}`
	d := testDispenser(input)

	d.Next() // dir1
	if got, want := d.RemainingArgs(), []string{"arg1", "arg2", "arg3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemainingArgs() = %v, want %v", got, want)
	}
	d.Next() // dir2
	if got, want := d.CountRemainingArgs(), 2; got != want {
		t.Errorf("CountRemainingArgs() = %d, want %d", got, want)
	}
	if got, want := d.RemainingArgs(), []string{"arg4", "arg5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemainingArgs() = %v, want %v", got, want)
	}
	d.Next() // dir3
	// RemainingArgs stops at the unquoted block-opening brace.
	if got, want := d.RemainingArgs(), []string{"arg6"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RemainingArgs() = %v, want %v", got, want)
	}
	if !d.NextBlock(0) || d.Val() != "sub" {
		t.Errorf("NextBlock() after RemainingArgs: val %q, want sub", d.Val())
	}
}

func TestDispenserReset(t *testing.T) {
	d := testDispenser(`dir {
sub
}`)
	d.Next()
	d.NextBlock(0)
	if d.Nesting() == 0 {
		t.Fatal("setup: expected to be inside block")
	}
	d.Reset()
	if d.Nesting() != 0 {
		t.Errorf("Nesting() = %d after Reset, want 0", d.Nesting())
	}
	if !d.Next() || d.Val() != "dir" {
		t.Errorf("Next() after Reset: val %q, want dir", d.Val())
	}
}

func TestDispenserErrors(t *testing.T) {
	d := NewDispenser([]Token{
		{File: "path/Caddyfile", Line: 12, Text: "dir"},
		{File: "path/Caddyfile", Line: 12, Text: "{"},
	})
	d.Next() // dir

	if got, want := d.Err("boom").Error(), "boom, at path/Caddyfile:12"; got != want {
		t.Errorf("Err() = %q, want %q", got, want)
	}
	if got, want := d.Errf("bad %s", "thing").Error(), "bad thing, at path/Caddyfile:12"; got != want {
		t.Errorf("Errf() = %q, want %q", got, want)
	}
	if got, want := d.EOFErr().Error(), "unexpected EOF, at path/Caddyfile:12"; got != want {
		t.Errorf("EOFErr() = %q, want %q", got, want)
	}
	if got, want := d.SyntaxErr("newline").Error(),
		"syntax error: unexpected token 'dir', expecting 'newline', at path/Caddyfile:12"; got != want {
		t.Errorf("SyntaxErr() = %q, want %q", got, want)
	}
	// ArgErr with the last-loaded value.
	if got, want := d.ArgErr().Error(),
		"wrong argument count or unexpected line ending after 'dir', at path/Caddyfile:12"; got != want {
		t.Errorf("ArgErr() = %q, want %q", got, want)
	}
	// ArgErr on a brace token.
	d.Next() // {
	if got, want := d.ArgErr().Error(),
		"unexpected token '{', expecting argument, at path/Caddyfile:12"; got != want {
		t.Errorf("ArgErr() = %q, want %q", got, want)
	}
}

func TestDispenserErrorsNoToken(t *testing.T) {
	d := NewDispenser(nil)
	if got, want := d.Err("boom").Error(), "boom, at :0"; got != want {
		t.Errorf("Err() with no token = %q, want %q", got, want)
	}
}
