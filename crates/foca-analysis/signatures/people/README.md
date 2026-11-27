# People-in-text language data

One file per language, loaded at build time by
`crates/foca-analysis/src/identity/textpeople/lang.rs`. All lists are self-made from common
given names, family names, positions and function words; they hold no personal data.

Add a language by creating `<code>.txt` and listing it in `LANGS` in `lang.rs`.

## Format

Sections start with `[name]`; `#` starts a comment. Words are separated by whitespace unless
noted.

| Section | Meaning |
|---|---|
| `[script]` | `cyrillic`, `latin`, `arabic`, `hebrew`, `han`, `kana`, `hangul`, `georgian`, `armenian` |
| `[common]` | Frequent function words used to guess the language of a text block |
| `[given_m]`, `[given_f]`, `[given]` | Given names (nominative), by gender when known |
| `[ambiguous]` | Given names that are also ordinary words: need a stronger cue |
| `[family]` | Family names (CJK: required, no spaces between family and given name) |
| `[surname_suffix]` | Endings of typical surnames (`-енко`, `-ski`, `-shvili`, `-yan`) |
| `[particles]` | Lowercase surname particles (`von`, `de`, `da`, `bin`) |
| `[honorifics]` | Words before a name (`Mr`, `Dr`, `Herr`, `пан`); dots are optional |
| `[after]` | Words right after a name (`先生`, `様`, `님`, `Jr`) |
| `[labels]` | Field labels followed by a name (`ПІБ`, `Name`, `姓名`) |
| `[titles]` | One per line: `label = variant; variant`. Variants are lowercase prefixes; a trailing `*` allows the word to continue |
| `[stop]` | Capitalised words that are never names (document words, institutions, places, months) |
