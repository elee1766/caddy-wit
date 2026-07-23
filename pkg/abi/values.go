package abi

import "context"

// Go value mapping used by Load/Store/LiftFlat/LowerFlat:
//
//	bool            -> bool
//	u8/u16/u32/u64  -> uint8/uint16/uint32/uint64
//	s8/s16/s32/s64  -> int8/int16/int32/int64
//	f32/f64         -> float32/float64
//	char            -> rune
//	string          -> string
//	enum            -> uint32 (case index)
//	own/borrow      -> uint32 (handle)
//	list<u8>        -> []byte (special case, both directions)
//	list<T>         -> []any
//	record/tuple    -> []any (fields in declaration order)
//	option<T>       -> Opt
//	result<T,E>     -> Res
//	variant         -> Var

// Opt is the Go representation of a component-model option value.
type Opt struct {
	Some bool
	Val  any // nil unless Some
}

// None is the empty option.
var None = Opt{}

// SomeVal returns an option carrying v.
func SomeVal(v any) Opt { return Opt{Some: true, Val: v} }

// Res is the Go representation of a component-model result value.
type Res struct {
	IsErr bool
	Val   any // ok payload or err payload; nil when the case has no payload
}

// OkVal returns a successful result carrying v (which may be nil).
func OkVal(v any) Res { return Res{Val: v} }

// ErrVal returns a failed result carrying v (which may be nil).
func ErrVal(v any) Res { return Res{IsErr: true, Val: v} }

// Var is the Go representation of a general variant value.
type Var struct {
	Case uint32
	Val  any // nil when the case has no payload
}

// Pair is a generic two-tuple used by typed wrappers above this package.
type Pair[A, B any] struct {
	V0 A
	V1 B
}

// GuestError is an error string returned by a guest through a
// result<..., string>. It distinguishes "the plugin reported an error" from
// host-side failures such as traps or missing exports.
type GuestError struct {
	Message string
}

func (e *GuestError) Error() string { return e.Message }

// ctxKey is the private context key namespace for this package.
type ctxKey int

const (
	ctxKeyTables ctxKey = iota
)

// WithTables attaches resource handle tables to ctx. Every guest call whose
// interface exports resources must run with tables attached.
func WithTables(ctx context.Context, t *ResourceTables) context.Context {
	return context.WithValue(ctx, ctxKeyTables, t)
}

// TablesFromContext returns the resource tables attached to ctx, or nil.
func TablesFromContext(ctx context.Context) *ResourceTables {
	t, _ := ctx.Value(ctxKeyTables).(*ResourceTables)
	return t
}
