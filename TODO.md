# TODO

Remaining protocol work identified while extending the constant tables.
Items are roughly ordered by value; each should land as its own PR with
tests, per the contribution rules in CLAUDE.md.

## Block metadata in EXPLORE results (in progress, `feat/block-metadata`)

`list_datablocks()` currently returns only name/number/rid. The EXPLORE
response of a block object carries more, all already known:

- `Block.KnowhowProtected` (0x9DC) — struct 0xD77 with `Mode` (BITSET16)
  and `Password`. Lets browse report "this block is know-how protected"
  instead of the DB silently missing its tag tree (or failing on the
  type-info read).
- `Block.BlockLanguage` (0x9DA, UINT16) — STL/LAD/FBD/SCL/GRAPH, for
  tooling that filters by language.
- `Block.Unlinked` (0x9DF, BOOL) — load-memory-only blocks, which
  `browse()` currently skips without saying why.
- `Block.CRC` (0x9E4), `Block.BlockNumber` (0x9D9).

Care: `_parse_explore_datablocks` is shared with the V1 SessionKey
browse path; both framings must keep working.

## The attribute/class metadata table

The wire format carries a full object schema: ~330 classes with ~1000
attributes, each with an ID, datatype, and an access-flags bitmask
(`NeedsLegitimization` 0x4000, `ApplicationWritable` 0x2,
`ChangeableInRun` 0x2000, `ClientReadonly` 0x400, `ServerOnly` 0x800,
`Persistent` 0x20, `Core` 0x10 ...). Adding it as a queryable table
would let the library answer "why did this attribute read fail" and
"which attributes can I write" systematically, and give `browse()` and
the tag catalog human-readable attribute names.

Break this into digestible slices rather than one 1000-entry dump:

1. An `AttributeFlags` IntFlag + decoder, with tests over the flags
   observed in existing fixtures. Small, self-contained.
2. Class/attribute tables for the classes the library already touches
   (ServerSession, DataBlock, Block, CPUexecUnit, ControllerArea,
   Subscription, AlarmSubsystem) — names and IDs only.
3. Optionally a generated full table later, if the slices prove useful.

Reference for the ID space: thomas-v2/S7CommPlusDriver/Core/Ids.cs and
the Wireshark S7CommPlus dissector.

## GetVariablesAddress (0x0590)

The one function the library defines a code for but cannot send:
resolve symbolic names to their access addresses in bulk.

Request (after the common base): `MaxNumber` (UDINT) and
`AddressResolve` (WSTRING list). Response: `AddressOut` (dynamic array
of UDINT), `Values` (sparse VARIANT array), `ErrorList` (sparse INT64).

A client method would look like:

    addresses = client.get_variables_address(["DB1.MyTag", "MyMTag"])

returning, per name, either the resolved address path or the error code.
Value: a single round trip replaces the per-DB type-info RID resolution
that `browse()` currently performs, and it works for names outside DBs.

Needs: request/response builders, a strict parser with malformed-input
tests, emulator support, and both clients in parity. Byte-exact tests
against a capture before trusting the layout — the reference tables
describe the fields but not their qualifier details.

## Operating-state change groundwork (#8)

`OperatingStateREQ` (0x877) on CPUexecUnit is the writable counterpart
of the state attribute the library reads, with request values
1=Stop, 2=Reset Retentive, 3=Run, 4=Run Redundant. The read side
(`OperatingState` 0xD9E: 8=run, 4=stop) cross-checks the existing
`get_cpu_state()`.

Do not ship a `set_operating_state()` write without hardware validation
of both transitions — the issue explicitly gates closure on real-PLC
RUN<->STOP traces, and a wrong write is a disruptive administrative
action. Instead: add the constants, and post the attribute/value facts
on #8 so a tester with a bench PLC can capture the trace.

## Smaller items

- `Block.BlockLanguage` code table (STL/LAD/FBD/SCL/GRAPH/...) for
  block-metadata reporting.
- `ServerSession.Roles` (305) plural — the full role mask, next to the
  single `Role` the secured-session detection reads.
- Surface `ProjectOMS == 0` ("no project on the controller") from the
  ServerSessionVersion struct as a distinct connect error; it currently
  masquerades as a generic session-setup failure.
- OMSSessionVersion negotiation (V1..V7, 64..448): the negotiated
  `SystemOMS` gates which optional request fields exist (`CheckInput`
  >=V5, `ExclTrimmers` >=V7, `IDSpace` >=V3). Worth exposing the
  negotiated value on the connection first, before any field-gating.
