#!/usr/bin/env python3
"""
Fetch TLS cipher suites from IANA and emit a Rust enum with strum_macros derives.

Improvements over the simple regex:
 - tolerates leading whitespace
 - handles multiple comma-separated hex codes on one line (emits one variant per code)
 - skips "Reserved"/"Unassigned" lines
 - ignores range expressions (e.g. 0x00-0x0F) for now
"""

import re
import requests
import sys

URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters.txt"

# Regex explanation:
# ^\s*                                  -> optional leading whitespace
# (0x[0-9A-Fa-f]{2,4}(?:\s*,\s*0x[0-9A-Fa-f]{2,4})*)
#                                       -> capture one or more hex codes, comma separated
# (?:\s*-\s*0x[0-9A-Fa-f]{2,4})?        -> optional range (we won't expand ranges)
# \s+([A-Za-z0-9_]+)                    -> capture the token-like name (TLS_...)
entry_re = re.compile(
    r'^\s*(0x[0-9A-Fa-f]{2,4}(?:\s*,\s*0x[0-9A-Fa-f]{2,4})*)(?:\s*-\s*0x[0-9A-Fa-f]{2,4})?\s+([A-Za-z0-9_]+)',
    re.ASCII
)

def fetch_text(url):
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text

def parse_entries(text):
    suites = []  # list of tuples (u16_value, name)
    for line in text.splitlines():
        # skip obvious non-data lines
        if not line or line.strip().startswith('#'):
            continue
        # skip lines that mention Reserved/Unassigned in the name area
        if re.search(r'\b(?:Reserved|Unassigned|Private Use|IANA Review)\b', line, re.IGNORECASE):
            continue

        m = entry_re.match(line)
        if not m:
            continue
        codes_text, name = m.groups()

        # only accept names that start with TLS_ (guard against other sections)
        if not name.startswith("TLS_"):
            continue

        # split multiple codes, e.g. "0x00, 0x01"
        codes = [c.strip() for c in codes_text.split(',')]
      # print(codes, name)
        for c in codes:
            # skip ranges like "0x00-0x0F" (we didn't capture them above), but be defensive:
            if '-' in c:
                continue
        try:
            val = int(codes[0], 16) << 8 | int(codes[1],16)
           # print(val, name, codes)
        except ValueError as e:
            print("Invalid code:", c, file=sys.stderr)
            continue
        # ensure fits in u16
        if 0 <= val <= 0xFFFF:
            suites.append((val, name))

    #print(suites)
    return suites

def emit_rust(suites):
    # sort by numeric code for nicer output
    suites = sorted(suites, key=lambda t: t[0])

    out_lines = []
    out_lines.append("use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};\n")
    out_lines.append("#[derive(EnumIter, EnumString, FromRepr, IntoStaticStr, Debug, Clone, Copy, PartialEq, Eq, Default)]")
    out_lines.append("#[repr(u16)]")
    out_lines.append("pub enum TlsCipherSuite {")
    out_lines.append("#[default]")
    last_name = None
    for val, name in suites:
        # Avoid duplicate variant names (different codes with same name) by appending code suffix if needed.
        variant_name = name
        # If name already used for a different code, disambiguate
        if last_name == variant_name:
            # append numeric suffix to avoid duplicate variant identifiers
            variant_name = f"{variant_name}_{val:04X}"
        out_lines.append(f"    {variant_name} = 0x{val:04X},")
        last_name = name
    out_lines.append("}\n")

    out_lines.append("""impl TlsCipherSuite {
    pub fn from_u16(id: u16) -> Option<Self> { Self::from_repr(id) }
    pub fn to_u16(self) -> u16 { self as u16 }
    pub fn as_str(self) -> &'static str { self.into() }
}""")
    return "\n".join(out_lines)

def main():
    try:
        text = fetch_text(URL)
    except Exception as e:
        print("Failed to fetch IANA registry:", e, file=sys.stderr)
        sys.exit(1)

    suites = parse_entries(text)
    if not suites:
        print("No suites parsed; the registry format may have changed.", file=sys.stderr)
        sys.exit(1)

    rust_src = emit_rust(suites)
    print(rust_src)

if __name__ == "__main__":
    main()
