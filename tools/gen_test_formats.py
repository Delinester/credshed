#!/usr/bin/env python3
"""
Generate SYNTHETIC credential-leak fixtures in a variety of real-world formats
so credshed's parser can be exercised on dirty / heterogeneous data.

ALL DATA PRODUCED HERE IS FAKE (randomly generated) and must never be treated
as real. It mimics the *shape* of public leak formats, not their contents.

Usage:
    python3 tools/gen_test_formats.py [output_dir] [--rows N]

Covered formats (one file each):
    01  email:password                      classic combolist
    02  email;password                      semicolon combolist
    03  username:password                   no-email combolist
    04  email:md5hash                        unsalted DB dump
    05  https://url:email:password          stealer-log ULP (with scheme)
    06  email|username|password             pipe-delimited dump
    07  email<TAB>username<TAB>password      tab-delimited dump
    08  id,email,username,password,phone     CSV with header
    09  INSERT INTO ... VALUES (...)         SQL dump
    10  {json per line}                      JSON-lines
    11  mixed/dirty                          junk headers, blanks, ragged rows,
                                             colon-in-password, unicode, missing fields
    12  url:phone:password                   ULP with phone logins
    13  email:pa:ss:word                     password contains the delimiter
"""

import sys
import json
import random
from pathlib import Path

SEED = 1337  # deterministic fixtures

FIRST = ['john', 'maria', 'alex', 'yuki', 'ahmed', 'olga', 'liam', 'sofia',
         'raj', 'chen', 'ivan', 'fatima', 'pedro', 'hana', 'noah', 'elena']
LAST = ['smith', 'garcia', 'kim', 'ivanov', 'khan', 'silva', 'muller', 'rossi',
        'tanaka', 'nguyen', 'kowalski', 'santos', 'novak', 'haddad']
MAIL_DOMAINS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                'mail.ru', 'yandex.ru', 'gmx.de', 'orange.fr', 'libero.it',
                'naver.com', 'qq.com', 'uol.com.br', 'web.de', 'proton.me']
CC_DOMAINS = ['example.ru', 'company.uz', 'firma.de', 'societe.fr', 'empresa.br',
              'shirkat.uz', 'biznes.kz', 'portal.ua', 'service.in', 'corp.us',
              'uni.ac.uk', 'gov.pl', 'shop.com.tr', 'bank.co.za']
SERVICES = ['accounts.google.com', 'login.live.com', 'github.com/login',
            'facebook.com/login', 'instagram.com', 'paypal.com', 'mega.nz',
            'account.apple.com', 'auth.qiwa.sa', 'id.vk.com', 'steamcommunity.com',
            'com.whatsapp', 'discord.com/login', 'netflix.com/login',
            'portal.gov.in', 'banking.sberbank.ru']
PW_PARTS = ['Sum', 'mer', '2024', 'qwe', 'rty', '!', 'P@ss', 'word', '123',
            'love', 'Dragon', 'x7', 'Zz', '_', '99', 'Admin', 'Moon']


def rnd_email(r):
    return f'{r.choice(FIRST)}.{r.choice(LAST)}{r.randint(1, 9999)}@{r.choice(MAIL_DOMAINS + CC_DOMAINS)}'

def rnd_user(r):
    return f'{r.choice(FIRST)}_{r.choice(LAST)}{r.randint(1, 999)}'

def rnd_pass(r):
    return ''.join(r.sample(PW_PARTS, r.randint(2, 4)))

def rnd_service(r):
    return r.choice(SERVICES)

def rnd_phone(r):
    cc = r.choice(['+1', '+44', '+7', '+998', '+91', '+55', '+49', '+223'])
    return cc + ''.join(str(r.randint(0, 9)) for _ in range(r.randint(9, 10)))

def rnd_md5(r):
    return ''.join(r.choice('0123456789abcdef') for _ in range(32))


def gen(out_dir, rows):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    r = random.Random(SEED)

    def lines(fn, make):
        p = out / fn
        with open(p, 'w', encoding='utf-8') as f:
            for _ in range(rows):
                f.write(make() + '\n')
        return p

    files = []
    files.append(lines('01_email_colon_pass.txt', lambda: f'{rnd_email(r)}:{rnd_pass(r)}'))
    files.append(lines('02_email_semicolon_pass.txt', lambda: f'{rnd_email(r)};{rnd_pass(r)}'))
    files.append(lines('03_user_pass.txt', lambda: f'{rnd_user(r)}:{rnd_pass(r)}'))
    files.append(lines('04_email_md5.txt', lambda: f'{rnd_email(r)}:{rnd_md5(r)}'))
    files.append(lines('05_ulp_http.txt', lambda: f'https://{rnd_service(r)}:{rnd_email(r)}:{rnd_pass(r)}'))
    files.append(lines('06_pipe.txt', lambda: f'{rnd_email(r)}|{rnd_user(r)}|{rnd_pass(r)}'))
    files.append(lines('07_tab.txt', lambda: f'{rnd_email(r)}\t{rnd_user(r)}\t{rnd_pass(r)}'))
    files.append(lines('12_url_phone_pass.txt', lambda: f'{rnd_service(r)}:{rnd_phone(r)}:{rnd_pass(r)}'))
    # password itself contains the delimiter (ragged field count)
    files.append(lines('13_colon_in_pass.txt',
                       lambda: rnd_email(r) + ':' + ':'.join(rnd_pass(r) for _ in range(r.randint(1, 4)))))

    # 08 CSV with header
    p = out / '08_csv_header.csv'
    with open(p, 'w', encoding='utf-8') as f:
        f.write('id,email,username,password,phone\n')
        for i in range(rows):
            f.write(f'{i},{rnd_email(r)},{rnd_user(r)},"{rnd_pass(r)}",{rnd_phone(r)}\n')
    files.append(p)

    # 09 SQL dump
    p = out / '09_sql_insert.sql'
    with open(p, 'w', encoding='utf-8') as f:
        f.write('-- MySQL dump\nINSERT INTO `users` (`id`,`email`,`pass`) VALUES\n')
        rowbuf = []
        for i in range(rows):
            rowbuf.append(f"('{i}','{rnd_email(r)}','{rnd_md5(r)}')")
            if len(rowbuf) == 20:
                f.write(','.join(rowbuf) + ';\n')
                f.write('INSERT INTO `users` (`id`,`email`,`pass`) VALUES\n')
                rowbuf = []
        if rowbuf:
            f.write(','.join(rowbuf) + ';\n')
    files.append(p)

    # 10 JSON-lines
    p = out / '10_jsonl.jsonl'
    with open(p, 'w', encoding='utf-8') as f:
        for _ in range(rows):
            f.write(json.dumps({'email': rnd_email(r), 'username': rnd_user(r),
                                'password': rnd_pass(r), 'url': rnd_service(r)}) + '\n')
    files.append(p)

    # 11 mixed / dirty - the torture test
    p = out / '11_mixed_dirty.txt'
    with open(p, 'w', encoding='utf-8') as f:
        f.write('######## FREE LEAK - follow @nobody ########\n')
        f.write('Greetings friends :)\n\n')
        for i in range(rows):
            k = i % 10
            if k == 0:
                f.write(f'{rnd_service(r)}:{rnd_email(r)}:{rnd_pass(r)}\n')          # ulp
            elif k == 1:
                f.write(f'{rnd_email(r)}:{rnd_pass(r)}\n')                            # combo
            elif k == 2:
                f.write(f'{rnd_user(r)}:{rnd_pass(r)}\n')                             # user:pass
            elif k == 3:
                f.write(f'{rnd_service(r)}:{rnd_phone(r)}:{rnd_pass(r)}\n')           # phone
            elif k == 4:
                f.write(f'{rnd_email(r)}:{rnd_pass(r)}:{rnd_pass(r)}:extra:{rnd_pass(r)}\n')  # ragged, colon pw
            elif k == 5:
                f.write('\n')                                                         # blank
            elif k == 6:
                f.write(f'{rnd_email(r)}\n')                                          # email only
            elif k == 7:
                f.write(f'   {rnd_service(r)} : {rnd_email(r)} : {rnd_pass(r)}  \n')  # whitespace padding
            elif k == 8:
                f.write(f'{rnd_user(r)}:café_{rnd_pass(r)}日本\n')                     # unicode
            else:
                f.write(f'garbage line with no delimiter {i} {rnd_user(r)}\n')        # junk
    files.append(p)

    def rnd_bcrypt(r):
        import string as _s
        b64 = _s.ascii_letters + _s.digits + './'
        return '$2y$10$' + ''.join(r.choice(b64) for _ in range(53))

    # 14 — stealer-log multi-line "Key: value" blocks (RedLine / Vidar style)
    p = out / '14_stealer_blocks.txt'
    with open(p, 'w', encoding='utf-8') as f:
        for i in range(rows):
            who = rnd_email(r) if i % 2 else rnd_user(r)
            f.write(f'SOFT: Google [Chrome] Default\nURL: https://{rnd_service(r)}\n'
                    f'USER: {who}\nPASS: {rnd_pass(r)}\n' + ('=' * 40) + '\n')
    files.append(p)

    # 15 — space-separated (email pass)
    files.append(lines('15_space.txt', lambda: f'{rnd_email(r)} {rnd_pass(r)}'))

    # 16 — email:hash:salt  (classic DB dump with a salt column)
    files.append(lines('16_email_hash_salt.txt', lambda: f'{rnd_email(r)}:{rnd_md5(r)}:{rnd_md5(r)[:8]}'))

    # 17 — hashcat potfile  (<hash>:<cracked plaintext>, no identity)
    files.append(lines('17_potfile.txt', lambda: f'{rnd_bcrypt(r)}:{rnd_pass(r)}'))

    # 18 — Latin-1 encoded names with accents
    p = out / '18_latin1.txt'
    with open(p, 'w', encoding='latin-1') as f:
        names = ['José', 'Müller', 'François', 'Søren', 'Ângela', 'Zoë']
        for i in range(rows):
            f.write(f'{r.choice(names)}{r.randint(1,99)}@{r.choice(CC_DOMAINS)}:{r.choice(names)}{r.randint(1,999)}\n')
    files.append(p)

    # 19 — UTF-8 with BOM + CSV header
    p = out / '19_bom_header.csv'
    with open(p, 'w', encoding='utf-8-sig') as f:
        f.write('login,secret,site\n')
        for _ in range(rows):
            f.write(f'{rnd_user(r)},{rnd_pass(r)},{rnd_service(r)}\n')
    files.append(p)

    # 20 — ULP with scheme + CRLF line endings (like a real stealer combo export)
    p = out / '20_scheme_crlf.txt'
    with open(p, 'wb') as f:
        for _ in range(rows):
            f.write(f'https://{rnd_service(r)}/login:{rnd_email(r)}:{rnd_pass(r)}\r\n'.encode('utf-8'))
    files.append(p)

    # 21 — pipe-delimited with padding spaces
    files.append(lines('21_pipe_pad.txt', lambda: f'{rnd_email(r)} | {rnd_user(r)} | {rnd_pass(r)}'))

    # 22 — ULP where the URL carries an explicit :port
    files.append(lines('22_url_port.txt', lambda: f'{rnd_service(r)}:{r.choice([8080,443,2082,21,25])}:{rnd_email(r)}:{rnd_pass(r)}'))

    return files


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    out_dir = args[0] if args else 'tests/fixtures/leak_formats'
    rows = 200
    if '--rows' in sys.argv:
        rows = int(sys.argv[sys.argv.index('--rows') + 1])
    made = gen(out_dir, rows)
    print(f'Wrote {len(made)} synthetic fixture(s) to {out_dir} ({rows} rows each):')
    for p in made:
        print(f'  {p}')
