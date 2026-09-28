# Monolith5: recovered compact Boolean model

This is an exact compact model of the pinned, generated Family-0 Monolith5,
not a runtime replacement or a claim about every proprietary DLL version.
Source and destination are little-endian 32-bit words, numbered from zero.

Monolith5 consumes 54 source words and produces 12 output words. Its generated
body is mostly bitwise logic, but unlike Monolith11 it contains fixed shifts
and multiplications by two. The bitwise-only truth-table method therefore does
not apply directly. `tools/trace_session_auth_bits.py` follows every output
bit through the versioned backward slice, including constant masks, logical
right shifts, left shifts, and power-of-two multiplication modulo 2³².

## Recovered formula

The 12 output words form two streams, each with six 28-bit payload limbs.
Payload bits occupy word bits 2–29; word bits 0, 1, 30, and 31 are always zero.
Let `A[t]` be the first stream's payload bits and `B[t]` the second stream's,
for `t = 0..167`. The first bit of the second stream is always zero: `B[0]=0`.

An input bit lane is a nine-bit vector: for source triplet `c` (0–5) and bit
position `p` (0–31), take bit `p` of source words `18*s + 3*c + j`, with span
`s = 0..2` and member `j = 0..2`. Place those nine bits at positions `3*s+j`
of the vector. Call one of the 32 recovered nine-input truth-table functions
on this vector `F_k(c,p)`.

Each position record selects two or three such lane functions `f₀, f₁, …`
and a constant `a`. The exact two-output formula is:

```text
A[t]   = a XOR f₀ XOR f₁ [XOR f₂]
B[t+1] = r XOR XOR { product(f_j for j in S) : S selected by mask }
```

Here `r` is zero except for the first position, where one extra nine-input
lane function supplies a boundary correction. A product is Boolean AND; the
empty product is one. No selected term contains all three functions, so the
second stream is at most quadratic in these lane functions. The 32 truth
tables, 168 position records, and masks are in
`tools/monolith5_model.json`; `tools/monolith5_model.py` evaluates this formula.
Both are analysis-only and leave the generated runtime code unchanged.
Every recovered lane function is symmetric under permutation of the three
72-byte input spans; the test suite checks all 512 inputs and all six span
permutations for every truth table.

## Dependency neighborhoods

The source-word neighborhoods repeat across the two six-word outputs:

| Output words | Possible source words in each of the three 18-word input spans |
| --- | --- |
| 0 and 6 | 0–2 |
| 1 and 7 | 0–5 |
| 2 and 8 | 0–8 |
| 3 and 9 | 0–2, 6–11 |
| 4 and 10 | 0–2, 9–14 |
| 5 and 11 | 0–2, 12–17 |

Add offsets 0, 18, and 36 to the second column for the three actual input
spans. For example, output word 0 can depend on source words 0–2, 18–20,
and 36–38. These are conservative *bit-level* dependencies from the earlier
trace: cancellation can remove an input. The symbolic recovery finds the
actual Boolean functions, including those cancellations.

Run the detailed trace with:

```bash
python -m tools.trace_session_auth_bits 5 0
python -m tools.trace_session_auth_bits 5 0 --json
```

## Equivalence and limits

`tools/recover_monolith5.py` symbolically interprets each output's versioned
backward slice using reduced ordered binary decision diagrams (ROBDDs). It
converts each exact Boolean function to its unique algebraic normal form,
checks the first-stream lane separation, factors every second-stream bit,
and deterministically regenerates the compact data. It rejects unsupported
operations, mixed first-stream lanes, unexpected factorization residuals,
nonzero padding bits, or a change in the expected function count. Verify the
checked-in model with:

```bash
python -m tools.recover_monolith5 --verify tools/monolith5_model.json
```

The test suite checks the symbolic engine on a small exhaustive expression,
regenerates and compares the complete saved model, checks the upstream
Monolith5 known-answer vector, and differentially compares 100 seeded random
inputs against the generated implementation. Thus the model is equivalent to
the pinned generated Monolith5 *within the supported uint32 expression and
sound backward-slice model*. It does not prove equivalence to every Siemens
DLL or firmware version, and it has not replaced the hardware-validated
runtime implementation.
