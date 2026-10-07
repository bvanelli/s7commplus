## Summary

<!-- What does this change and why? One coherent purpose per pull request. -->

## Sources

<!--
For every new protocol constant, id, enum value or table entry, say where it
comes from: a packet capture, a Wireshark dissector table, or a specific
file and line of a reference implementation. Name the file that really
contains the value; a citation to a file that does not list it cannot be
checked. Say so when a value is a guess or only seen on one PLC and firmware.
-->

## Tests

<!-- Byte-exact tests for encoders and decoders, plus malformed and truncated input. -->

## Checklist

- [ ] `pytest`, `mypy s7commplus`, `ruff check` and `ruff format --check` pass
- [ ] `CHANGES.md` has an entry under the unreleased heading for user-visible changes
- [ ] `README.md`, `__all__` and the docs are updated for public API changes
- [ ] Parsers treat PLC data as untrusted (lengths, offsets and truncation are checked)
