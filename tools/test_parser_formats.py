#!/usr/bin/env python3
"""
Parse every synthetic fixture with SmartParse and report format detection +
capture rate + field coverage.  A quick regression harness for the parser.

Usage:
    python3 tools/test_parser_formats.py [fixtures_dir]
"""
import sys
import collections
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.parser import SmartParse  # noqa: E402

EXPECT = {  # filename -> expected detected format
    '01_email_colon_pass.txt': 'combo',
    '02_email_semicolon_pass.txt': 'combo',
    '03_user_pass.txt': 'combo',
    '04_email_md5.txt': 'combo',
    '05_ulp_http.txt': 'ulp',
    '06_pipe.txt': 'generic',
    '07_tab.txt': 'generic',
    '08_csv_header.csv': 'csv',
    '09_sql_insert.sql': {'generic', 'combo', 'mixed'},
    '10_jsonl.jsonl': 'jsonl',
    '11_mixed_dirty.txt': {'mixed', 'combo', 'ulp'},
    '12_url_phone_pass.txt': 'ulp',
    '13_colon_in_pass.txt': 'combo',
    '14_stealer_blocks.txt': 'blocks',
    '15_space.txt': {'combo', 'generic', 'mixed'},
    '16_email_hash_salt.txt': 'generic',
    '17_potfile.txt': {'combo', 'mixed', 'generic'},
    '18_latin1.txt': 'combo',
    '19_bom_header.csv': 'csv',
    '20_scheme_crlf.txt': 'ulp',
    '21_pipe_pad.txt': 'generic',
    '22_url_port.txt': {'ulp', 'generic'},
}


def check(path):
    p = SmartParse(path)
    has = collections.Counter()
    n = 0
    sample = []
    for acc in p:
        n += 1
        for f in ('email', 'username', 'phone', 'service', 'password'):
            if getattr(acc, f):
                has[f] += 1
        if acc.hashes:
            has['hash'] += 1
        if len(sample) < 2:
            sample.append(str(acc))
    nonblank = p.stats['lines_total'] - p.stats['lines_blank']
    cap = 100 * n / max(1, nonblank)
    return p.format, n, cap, dict(has), sample, dict(p.stats)


def main():
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('tests/fixtures/leak_formats')
    files = sorted(d.glob('*'))
    if not files:
        print(f'No fixtures in {d}. Run tools/gen_test_formats.py first.')
        return 1
    print(f'{"file":30} {"format":9} {"accts":>7} {"cap%":>6}  fields')
    print('-' * 90)
    ok = True
    for f in files:
        try:
            fmt, n, cap, has, sample, stats = check(f)
            exp = EXPECT.get(f.name)
            match = (fmt == exp) if isinstance(exp, str) else (exp is None or fmt in exp)
            flag = '' if match else f'  <-- expected {exp}'
            if not match:
                ok = False
            fieldstr = ' '.join(f'{k}:{v}' for k, v in sorted(has.items()))
            print(f'{f.name:30} {fmt:9} {n:>7,} {cap:>5.1f}%  {fieldstr}{flag}')
        except Exception as e:
            ok = False
            import traceback
            print(f'{f.name:30} ERROR: {e}')
            traceback.print_exc()
    print('-' * 90)
    print('ALL FORMATS DETECTED AS EXPECTED' if ok else 'SOME FORMATS MISDETECTED (see above)')
    return 0 if ok else 2


if __name__ == '__main__':
    sys.exit(main())
