//! Caddyfile token Dispenser for caddy-wit Rust plugins.
//!
//! Mirrors the API and semantics of the Go SDK's `caddyfile.Dispenser`
//! (and caddy's native `caddyconfig/caddyfile.Dispenser`), so guest
//! plugin code reads like native Caddy plugin code.
//!
//! No dependencies — pure parsing logic.

/// A single Caddyfile token as delivered over the WIT
/// `caddy:plugin/config.token` record.
///
/// `quoted` reports whether the token was enclosed in quotes (double
/// quotes, backticks, or heredoc) in the Caddyfile; it lets the
/// Dispenser distinguish a literal `"{"` argument from a block-opening
/// brace.
#[derive(Debug, Clone)]
pub struct Token {
    pub file: String,
    pub line: u32,
    pub text: String,
    pub quoted: bool,
}

impl Token {
    /// Create a new token. Convenience constructor for converting from
    /// WIT-generated token types.
    pub fn new(file: &str, line: u32, text: &str, quoted: bool) -> Self {
        Token {
            file: file.to_string(),
            line,
            text: text.to_string(),
            quoted,
        }
    }

    /// Count how many line breaks are in the token text.
    fn num_line_breaks(&self) -> u32 {
        self.text.matches('\n').count() as u32
    }
}

/// Dispenser dispenses tokens with some notion of structure, similarly
/// to a lexer. An empty Dispenser is invalid; call `Dispenser::new` to
/// make a proper instance.
pub struct Dispenser {
    tokens: Vec<Token>,
    cursor: isize,
    nesting: i32,
}

impl Dispenser {
    /// Create a new Dispenser filled with the given tokens.
    pub fn new(tokens: Vec<Token>) -> Self {
        Dispenser {
            tokens,
            cursor: -1,
            nesting: 0,
        }
    }

    // ── Navigation ──────────────────────────────────────────────────

    /// Advance to the next token. Returns true if a token was loaded;
    /// false if all tokens have been consumed.
    pub fn next(&mut self) -> bool {
        if self.cursor < self.tokens.len() as isize - 1 {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Move to the previous token. Returns true if the cursor ends up
    /// pointing to a valid token. May decrement to -1 so the next call
    /// to `next()` points to the first token.
    pub fn prev(&mut self) -> bool {
        if self.cursor > -1 {
            self.cursor -= 1;
            return self.cursor > -1;
        }
        false
    }

    /// Advance if the next token is on the same line and is not a
    /// block opening (unquoted `{`). Returns true if an argument
    /// token was loaded. A quoted `"{"` is a literal argument, not a
    /// block opening.
    pub fn next_arg(&mut self) -> bool {
        if !self.next_on_same_line() {
            return false;
        }
        if self.is_open_curly_brace() {
            // roll back; a block opening is not an argument
            self.cursor -= 1;
            return false;
        }
        true
    }

    /// Advance to the first token on a new line. Returns true if a
    /// token was loaded; false if there is no next token or it is on
    /// the same line.
    pub fn next_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= self.tokens.len() as isize - 1 {
            return false;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        if is_next_on_new_line(curr, next) {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Block iteration. Can be used as the condition of a loop to load
    /// the next token as long as it opens a block or is already in a
    /// block nested more than `initial_nesting_level`.
    ///
    /// Proper use:
    /// ```ignore
    /// let nesting = d.nesting();
    /// while d.next_block(nesting) {
    ///     // ...
    /// }
    /// ```
    ///
    /// Or for a fresh dispenser:
    /// ```ignore
    /// while d.next_block(0) {
    ///     // ...
    /// }
    /// ```
    pub fn next_block(&mut self, initial_nesting_level: i32) -> bool {
        if self.nesting > initial_nesting_level {
            if !self.next() {
                return false; // should be EOF error
            }
            if self.is_close_curly_brace() && !self.next_on_same_line() {
                self.nesting -= 1;
            } else if self.is_open_curly_brace() && !self.next_on_same_line() {
                self.nesting += 1;
            }
            return self.nesting > initial_nesting_level;
        }
        if !self.next_on_same_line() {
            // block must open on same line
            return false;
        }
        if !self.is_open_curly_brace() {
            self.cursor -= 1; // roll back if not opening brace
            return false;
        }
        self.next(); // consume open curly brace
        if self.is_close_curly_brace() {
            return false; // open and then closed right away
        }
        self.nesting += 1;
        true
    }

    // ── Accessors ───────────────────────────────────────────────────

    /// Current nesting level.
    pub fn nesting(&self) -> i32 {
        self.nesting
    }

    /// Text of the current token. Empty string if no token is loaded.
    pub fn val(&self) -> &str {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return "";
        }
        &self.tokens[self.cursor as usize].text
    }

    /// Line number of the current token. 0 if no token is loaded.
    pub fn line(&self) -> u32 {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return 0;
        }
        self.tokens[self.cursor as usize].line
    }

    /// Filename where the current token originated. Empty if no token.
    pub fn file(&self) -> &str {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return "";
        }
        &self.tokens[self.cursor as usize].file
    }

    /// Whether the current token was quoted in the Caddyfile.
    pub fn quoted(&self) -> bool {
        if self.cursor < 0 || self.cursor >= self.tokens.len() as isize {
            return false;
        }
        self.tokens[self.cursor as usize].quoted
    }

    // ── Argument helpers ────────────────────────────────────────────

    /// Fill `targets` with the next arguments (tokens on the same
    /// line). Returns true if all targets were filled; false if not
    /// enough argument tokens remain.
    pub fn args(&mut self, targets: &mut [&mut String]) -> bool {
        for target in targets.iter_mut() {
            if !self.next_arg() {
                return false;
            }
            **target = self.val().to_string();
        }
        true
    }

    /// Like `args`, but also checks that no more argument tokens
    /// remain on the line. Returns true only if the exact number of
    /// targets matches the remaining arguments.
    pub fn all_args(&mut self, targets: &mut [&mut String]) -> bool {
        if !self.args(targets) {
            return false;
        }
        if self.next_arg() {
            self.prev();
            return false;
        }
        true
    }

    /// Load any remaining arguments (tokens on the same line) into a
    /// Vec and return them. Unquoted `{` also ends arguments.
    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.val().to_string());
        }
        args
    }

    /// Count remaining arguments without consuming tokens.
    pub fn count_remaining_args(&mut self) -> usize {
        let saved_cursor = self.cursor;
        let mut count = 0usize;
        while self.next_arg() {
            count += 1;
        }
        self.cursor = saved_cursor;
        count
    }

    /// Reset the dispenser to the beginning, as if newly constructed.
    pub fn reset(&mut self) {
        self.cursor = -1;
        self.nesting = 0;
    }

    // ── Error helpers ───────────────────────────────────────────────

    /// Argument error: another argument was expected but not found.
    pub fn arg_err(&self) -> String {
        if self.val() == "{" {
            return self.err("unexpected token '{', expecting argument");
        }
        self.errf(&format!(
            "wrong argument count or unexpected line ending after '{}'",
            self.val()
        ))
    }

    /// Generic syntax error explaining what was found and expected.
    pub fn syntax_err(&self, expected: &str) -> String {
        format!(
            "syntax error: unexpected token '{}', expecting '{}', at {}:{}",
            self.val(),
            expected,
            self.file(),
            self.line()
        )
    }

    /// Custom parse-time error with location.
    pub fn err(&self, msg: &str) -> String {
        format!("{}, at {}:{}", msg, self.file(), self.line())
    }

    /// Same as `err` — in Rust callers use `format!()` before calling.
    pub fn errf(&self, msg: &str) -> String {
        self.err(msg)
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Advance the cursor if the next token is on the same line of the
    /// same file.
    fn next_on_same_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= self.tokens.len() as isize - 1 {
            return false;
        }
        let idx = self.cursor as usize;
        if !is_next_on_new_line(&self.tokens[idx], &self.tokens[idx + 1]) {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Reports whether the current token is an unquoted `{`.
    fn is_open_curly_brace(&self) -> bool {
        self.val() == "{" && !self.quoted()
    }

    /// Reports whether the current token is an unquoted `}`.
    fn is_close_curly_brace(&self) -> bool {
        self.val() == "}" && !self.quoted()
    }
}

/// Determines whether `t2` is on a different line (higher line number)
/// than `t1`, accounting for line breaks inside `t1`'s text.
fn is_next_on_new_line(t1: &Token, t2: &Token) -> bool {
    if t1.file != t2.file {
        return true;
    }
    t1.line + t1.num_line_breaks() < t2.line
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple lexer for tests: splits each line on whitespace. A field
    /// wrapped in double quotes becomes a quoted token with quotes
    /// stripped (matching what caddy's lexer produces).
    fn lex(input: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        for (i, line) in input.lines().enumerate() {
            for field in line.split_whitespace() {
                let mut tok = Token::new("Testfile", (i + 1) as u32, field, false);
                if field.len() >= 2 && field.starts_with('"') && field.ends_with('"') {
                    tok.text = field[1..field.len() - 1].to_string();
                    tok.quoted = true;
                }
                tokens.push(tok);
            }
        }
        tokens
    }

    fn test_dispenser(input: &str) -> Dispenser {
        Dispenser::new(lex(input))
    }

    #[test]
    fn test_val_next() {
        let input = "host:port\ndir1 arg1\ndir2 arg2 arg3\ndir3";
        let mut d = test_dispenser(input);

        assert_eq!(d.val(), "", "Val before Next should be empty");

        let expected = ["host:port", "dir1", "arg1", "dir2", "arg2", "arg3", "dir3"];
        for (i, want) in expected.iter().enumerate() {
            assert!(d.next(), "Next step {i}: expected true");
            assert_eq!(d.val(), *want, "Val step {i}");
        }
        assert!(!d.next(), "Next at EOF should be false");
        assert_eq!(d.val(), "dir3", "Val after EOF should keep last token");
    }

    #[test]
    fn test_next_arg() {
        let input = "dir1 arg1\ndir2 arg2 arg3\ndir3";
        let mut d = test_dispenser(input);

        assert!(d.next());
        assert_eq!(d.val(), "dir1");
        assert!(d.next_arg());
        assert_eq!(d.val(), "arg1");
        assert!(!d.next_arg(), "no more args on line 1");

        assert!(d.next());
        assert_eq!(d.val(), "dir2");
        assert!(d.next_arg());
        assert_eq!(d.val(), "arg2");
        assert!(d.next_arg());
        assert_eq!(d.val(), "arg3");
        assert!(!d.next_arg(), "no more args on line 2");

        assert!(d.next());
        assert_eq!(d.val(), "dir3");
        assert!(!d.next(), "EOF");
    }

    #[test]
    fn test_next_line() {
        let input = "host:port\ndir1 arg1";
        let mut d = test_dispenser(input);

        assert!(d.next_line(), "first token");
        assert_eq!(d.val(), "host:port");
        assert!(d.next_line(), "next token on new line");
        assert_eq!(d.val(), "dir1");
        assert!(!d.next_line(), "arg1 is on same line");
    }

    #[test]
    fn test_next_block() {
        let input = "foobar1 {\nsub1 arg1\nsub2\n}\nfoobar2 {\n}";
        let mut d = test_dispenser(input);

        // no block open yet
        assert!(!d.next_block(0));
        assert_eq!(d.nesting(), 0);

        d.next(); // foobar1
        assert!(d.next_block(0)); // enters block, loads sub1
        assert_eq!(d.nesting(), 1);
        assert_eq!(d.val(), "sub1");

        assert!(d.next_block(0)); // arg1
        assert_eq!(d.nesting(), 1);
        assert!(d.next_block(0)); // sub2
        assert_eq!(d.nesting(), 1);
        assert!(!d.next_block(0)); // closes block
        assert_eq!(d.nesting(), 0);

        d.next(); // foobar2
        assert!(!d.next_block(0)); // empty block
        assert_eq!(d.nesting(), 0);
    }

    #[test]
    fn test_nested_blocks() {
        let input = "dir {\ninner {\nx y\n}\nz\n}";
        let mut d = test_dispenser(input);

        d.next(); // dir
        let mut got = Vec::new();
        let outer = d.nesting();
        while d.next_block(outer) {
            if d.val() != "inner" {
                got.push(d.val().to_string());
                continue;
            }
            let inner = d.nesting();
            while d.next_block(inner) {
                got.push(format!("inner.{}", d.val()));
            }
        }
        assert_eq!(got, vec!["inner.x", "inner.y", "z"]);
        assert_eq!(d.nesting(), 0);
    }

    #[test]
    fn test_quoted_brace_is_argument() {
        let mut d = Dispenser::new(vec![
            Token::new("Caddyfile", 1, "dir", false),
            Token::new("Caddyfile", 1, "{", true),
            Token::new("Caddyfile", 1, "tail", false),
        ]);
        d.next(); // dir
        assert!(d.next_arg(), "quoted {{ must be loaded as argument");
        assert_eq!(d.val(), "{");
        assert!(d.next_arg());
        assert_eq!(d.val(), "tail");
    }

    #[test]
    fn test_quoted_brace_does_not_open_block() {
        let mut d = Dispenser::new(vec![
            Token::new("Caddyfile", 1, "dir", false),
            Token::new("Caddyfile", 1, "{", true),
        ]);
        d.next(); // dir
        assert!(!d.next_block(0), "quoted {{ must not open a block");
        assert!(d.next_arg());
        assert_eq!(d.val(), "{");
    }

    #[test]
    fn test_unquoted_brace_opens_block() {
        let mut d = Dispenser::new(vec![
            Token::new("Caddyfile", 1, "dir", false),
            Token::new("Caddyfile", 1, "{", false),
            Token::new("Caddyfile", 2, "sub", false),
            Token::new("Caddyfile", 3, "}", false),
        ]);
        d.next(); // dir
        assert!(!d.next_arg(), "unquoted {{ is not an argument");
        assert!(d.next_block(0), "unquoted {{ must open a block");
        assert_eq!(d.val(), "sub");
    }

    #[test]
    fn test_quoted_remaining_args() {
        let mut d = test_dispenser(r#"dir a "{" b "}" c"#);
        d.next();
        let got = d.remaining_args();
        assert_eq!(got, vec!["a", "{", "b", "}", "c"]);
    }

    #[test]
    fn test_args_all_args() {
        let input = "dir a b c\ndir2 x";
        let mut d = test_dispenser(input);

        d.next(); // dir
        let mut s1 = String::new();
        let mut s2 = String::new();
        assert!(d.args(&mut [&mut s1, &mut s2]));
        assert_eq!(s1, "a");
        assert_eq!(s2, "b");

        let mut s3 = String::new();
        let mut s4 = String::new();
        assert!(!d.args(&mut [&mut s3, &mut s4]), "not enough args remain");
        assert_eq!(s3, "c");
        assert_eq!(s4, "");

        d.reset();
        d.next(); // dir
        let mut t1 = String::new();
        let mut t2 = String::new();
        assert!(!d.all_args(&mut [&mut t1, &mut t2]), "3 args for 2 targets");

        d.reset();
        d.next(); // dir
        let mut u1 = String::new();
        let mut u2 = String::new();
        let mut u3 = String::new();
        assert!(d.all_args(&mut [&mut u1, &mut u2, &mut u3]));
        assert_eq!((u1.as_str(), u2.as_str(), u3.as_str()), ("a", "b", "c"));
    }

    #[test]
    fn test_remaining_args() {
        let input = "dir1 arg1 arg2 arg3\ndir2 arg4 arg5\ndir3 arg6 {\nsub\n}";
        let mut d = test_dispenser(input);

        d.next(); // dir1
        assert_eq!(d.remaining_args(), vec!["arg1", "arg2", "arg3"]);

        d.next(); // dir2
        assert_eq!(d.count_remaining_args(), 2);
        assert_eq!(d.remaining_args(), vec!["arg4", "arg5"]);

        d.next(); // dir3
        // remaining_args stops at unquoted block-opening brace
        assert_eq!(d.remaining_args(), vec!["arg6"]);
        assert!(d.next_block(0));
        assert_eq!(d.val(), "sub");
    }

    #[test]
    fn test_reset() {
        let mut d = test_dispenser("dir {\nsub\n}");
        d.next();
        d.next_block(0);
        assert_ne!(d.nesting(), 0, "should be inside block");
        d.reset();
        assert_eq!(d.nesting(), 0, "nesting reset");
        assert!(d.next());
        assert_eq!(d.val(), "dir");
    }

    #[test]
    fn test_errors() {
        let mut d = Dispenser::new(vec![
            Token::new("path/Caddyfile", 12, "dir", false),
            Token::new("path/Caddyfile", 12, "{", false),
        ]);
        d.next(); // dir

        assert_eq!(d.err("boom"), "boom, at path/Caddyfile:12");
        assert_eq!(
            d.errf(&format!("bad {}", "thing")),
            "bad thing, at path/Caddyfile:12"
        );
        assert_eq!(
            d.syntax_err("newline"),
            "syntax error: unexpected token 'dir', expecting 'newline', at path/Caddyfile:12"
        );
        assert_eq!(
            d.arg_err(),
            "wrong argument count or unexpected line ending after 'dir', at path/Caddyfile:12"
        );

        d.next(); // {
        assert_eq!(
            d.arg_err(),
            "unexpected token '{', expecting argument, at path/Caddyfile:12"
        );
    }

    #[test]
    fn test_errors_no_token() {
        let d = Dispenser::new(vec![]);
        assert_eq!(d.err("boom"), "boom, at :0");
    }
}
