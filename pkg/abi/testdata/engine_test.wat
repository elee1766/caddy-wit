;; Minimal canonical-ABI-shaped guest used by engine_wazero_test.go.
;; Regenerate the .wasm with:
;;   wasm-tools parse pkg/abi/testdata/engine_test.wat -o pkg/abi/testdata/engine_test.wasm
(module
  ;; host import: upper(s: string) -> string
  ;; flat results (ptr,len) > 1, so the guest passes a trailing retptr param.
  (import "test" "upper" (func $upper (param i32 i32 i32)))

  (memory (export "memory") 1)

  ;; Trivial bump allocator; heap starts above the fixed scratch areas.
  (global $heap (mut i32) (i32.const 1024))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    ;; p = (heap + align - 1) & ~(align - 1)
    global.get $heap
    local.get 2
    i32.add
    i32.const 1
    i32.sub
    local.get 2
    i32.const 1
    i32.sub
    i32.const -1
    i32.xor
    i32.and
    local.set $p
    ;; heap = p + size
    local.get $p
    local.get 3
    i32.add
    global.set $heap
    local.get $p)

  ;; add(a: u32, b: u32) -> u32   (single flat result, direct return)
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)

  ;; echo(s: string) -> string   (indirect result: returns pointer to area)
  (func (export "echo") (param $ptr i32) (param $len i32) (result i32)
    (i32.store (i32.const 512) (local.get $ptr))
    (i32.store (i32.const 516) (local.get $len))
    i32.const 512)

  ;; call-upper(s: string) -> string  (calls the host import through retptr)
  (func (export "call-upper") (param $ptr i32) (param $len i32) (result i32)
    local.get $ptr
    local.get $len
    i32.const 640
    call $upper
    i32.const 640)
)
