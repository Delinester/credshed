#!/usr/bin/env python3

# Credshed DFIR enhancement
# Maps top-level domains (TLDs) to countries / regions so that credential
# data can be sliced "by domain zone" (.ru, .uz, .us, ...) with a
# human-readable regional breakdown, the way a DFIR investigator thinks
# about exposure ("how much of this dump is Russian / Brazilian / Gulf?").

# ISO-3166 country-code TLDs -> (Country, Region).  Not exhaustive of every
# delegated ccTLD, but covers the ones that actually show up in real-world
# credential dumps plus every G20 / major market.
CCTLD = {
    # --- Eastern Europe / CIS ---
    'ru': ('Russia', 'Eastern Europe / CIS'),
    'su': ('Soviet Union (legacy)', 'Eastern Europe / CIS'),
    'by': ('Belarus', 'Eastern Europe / CIS'),
    'ua': ('Ukraine', 'Eastern Europe / CIS'),
    'kz': ('Kazakhstan', 'Central Asia'),
    'uz': ('Uzbekistan', 'Central Asia'),
    'kg': ('Kyrgyzstan', 'Central Asia'),
    'tj': ('Tajikistan', 'Central Asia'),
    'tm': ('Turkmenistan', 'Central Asia'),
    'am': ('Armenia', 'Caucasus'),
    'az': ('Azerbaijan', 'Caucasus'),
    'ge': ('Georgia', 'Caucasus'),
    'md': ('Moldova', 'Eastern Europe / CIS'),
    # --- Europe ---
    'de': ('Germany', 'Western Europe'),
    'fr': ('France', 'Western Europe'),
    'uk': ('United Kingdom', 'Western Europe'),
    'gb': ('United Kingdom', 'Western Europe'),
    'ie': ('Ireland', 'Western Europe'),
    'nl': ('Netherlands', 'Western Europe'),
    'be': ('Belgium', 'Western Europe'),
    'lu': ('Luxembourg', 'Western Europe'),
    'ch': ('Switzerland', 'Western Europe'),
    'at': ('Austria', 'Western Europe'),
    'es': ('Spain', 'Southern Europe'),
    'pt': ('Portugal', 'Southern Europe'),
    'it': ('Italy', 'Southern Europe'),
    'gr': ('Greece', 'Southern Europe'),
    'mt': ('Malta', 'Southern Europe'),
    'cy': ('Cyprus', 'Southern Europe'),
    'pl': ('Poland', 'Central Europe'),
    'cz': ('Czechia', 'Central Europe'),
    'sk': ('Slovakia', 'Central Europe'),
    'hu': ('Hungary', 'Central Europe'),
    'ro': ('Romania', 'Central Europe'),
    'bg': ('Bulgaria', 'Central Europe'),
    'si': ('Slovenia', 'Central Europe'),
    'hr': ('Croatia', 'Central Europe'),
    'rs': ('Serbia', 'Central Europe'),
    'ba': ('Bosnia and Herzegovina', 'Central Europe'),
    'mk': ('North Macedonia', 'Central Europe'),
    'al': ('Albania', 'Central Europe'),
    'me': ('Montenegro', 'Central Europe'),
    'se': ('Sweden', 'Nordics'),
    'no': ('Norway', 'Nordics'),
    'fi': ('Finland', 'Nordics'),
    'dk': ('Denmark', 'Nordics'),
    'is': ('Iceland', 'Nordics'),
    'ee': ('Estonia', 'Baltics'),
    'lv': ('Latvia', 'Baltics'),
    'lt': ('Lithuania', 'Baltics'),
    # --- North America ---
    'us': ('United States', 'North America'),
    'ca': ('Canada', 'North America'),
    'mx': ('Mexico', 'Latin America'),
    # --- Latin America ---
    'br': ('Brazil', 'Latin America'),
    'ar': ('Argentina', 'Latin America'),
    'cl': ('Chile', 'Latin America'),
    'co': ('Colombia', 'Latin America'),
    'pe': ('Peru', 'Latin America'),
    've': ('Venezuela', 'Latin America'),
    'ec': ('Ecuador', 'Latin America'),
    'uy': ('Uruguay', 'Latin America'),
    'py': ('Paraguay', 'Latin America'),
    'bo': ('Bolivia', 'Latin America'),
    'cr': ('Costa Rica', 'Latin America'),
    'pa': ('Panama', 'Latin America'),
    'gt': ('Guatemala', 'Latin America'),
    'do': ('Dominican Republic', 'Latin America'),
    'cu': ('Cuba', 'Latin America'),
    # --- Middle East ---
    'tr': ('Turkey', 'Middle East'),
    'sa': ('Saudi Arabia', 'Middle East / Gulf'),
    'ae': ('United Arab Emirates', 'Middle East / Gulf'),
    'qa': ('Qatar', 'Middle East / Gulf'),
    'kw': ('Kuwait', 'Middle East / Gulf'),
    'bh': ('Bahrain', 'Middle East / Gulf'),
    'om': ('Oman', 'Middle East / Gulf'),
    'il': ('Israel', 'Middle East'),
    'ir': ('Iran', 'Middle East'),
    'iq': ('Iraq', 'Middle East'),
    'jo': ('Jordan', 'Middle East'),
    'lb': ('Lebanon', 'Middle East'),
    'sy': ('Syria', 'Middle East'),
    'ye': ('Yemen', 'Middle East'),
    'ps': ('Palestine', 'Middle East'),
    # --- Africa ---
    'za': ('South Africa', 'Africa'),
    'ng': ('Nigeria', 'Africa'),
    'ke': ('Kenya', 'Africa'),
    'eg': ('Egypt', 'Africa / North'),
    'ma': ('Morocco', 'Africa / North'),
    'dz': ('Algeria', 'Africa / North'),
    'tn': ('Tunisia', 'Africa / North'),
    'ly': ('Libya', 'Africa / North'),
    'gh': ('Ghana', 'Africa'),
    'tz': ('Tanzania', 'Africa'),
    'ug': ('Uganda', 'Africa'),
    'et': ('Ethiopia', 'Africa'),
    'ci': ("Cote d'Ivoire", 'Africa'),
    'cm': ('Cameroon', 'Africa'),
    'sn': ('Senegal', 'Africa'),
    'zw': ('Zimbabwe', 'Africa'),
    'zm': ('Zambia', 'Africa'),
    'ao': ('Angola', 'Africa'),
    'mz': ('Mozambique', 'Africa'),
    'rw': ('Rwanda', 'Africa'),
    # --- Asia / Pacific ---
    'cn': ('China', 'East Asia'),
    'jp': ('Japan', 'East Asia'),
    'kr': ('South Korea', 'East Asia'),
    'kp': ('North Korea', 'East Asia'),
    'tw': ('Taiwan', 'East Asia'),
    'hk': ('Hong Kong', 'East Asia'),
    'mo': ('Macau', 'East Asia'),
    'mn': ('Mongolia', 'East Asia'),
    'in': ('India', 'South Asia'),
    'pk': ('Pakistan', 'South Asia'),
    'bd': ('Bangladesh', 'South Asia'),
    'lk': ('Sri Lanka', 'South Asia'),
    'np': ('Nepal', 'South Asia'),
    'af': ('Afghanistan', 'South Asia'),
    'bt': ('Bhutan', 'South Asia'),
    'mv': ('Maldives', 'South Asia'),
    'id': ('Indonesia', 'Southeast Asia'),
    'my': ('Malaysia', 'Southeast Asia'),
    'sg': ('Singapore', 'Southeast Asia'),
    'th': ('Thailand', 'Southeast Asia'),
    'vn': ('Vietnam', 'Southeast Asia'),
    'ph': ('Philippines', 'Southeast Asia'),
    'kh': ('Cambodia', 'Southeast Asia'),
    'la': ('Laos', 'Southeast Asia'),
    'mm': ('Myanmar', 'Southeast Asia'),
    'bn': ('Brunei', 'Southeast Asia'),
    'au': ('Australia', 'Oceania'),
    'nz': ('New Zealand', 'Oceania'),
    'fj': ('Fiji', 'Oceania'),
    'pg': ('Papua New Guinea', 'Oceania'),
}

# Generic / sponsored TLDs that are NOT tied to a country.  These get grouped
# under a "Generic (gTLD)" region so regional stats aren't skewed by .com.
GTLD = {
    'com', 'net', 'org', 'info', 'biz', 'name', 'pro', 'mobi', 'xyz', 'top',
    'site', 'online', 'club', 'shop', 'app', 'dev', 'io', 'ai', 'co', 'tv',
    'me', 'cc', 'ws', 'live', 'life', 'world', 'vip', 'icu', 'cloud', 'store',
    'tech', 'space', 'website', 'fun', 'link', 'click', 'email', 'blog',
    'edu', 'gov', 'mil', 'int', 'arpa',
}

# ccTLDs that are commonly used generically (sold worldwide), kept here so an
# investigator knows the regional signal is weak.
GENERIC_CCTLD = {'io', 'co', 'tv', 'me', 'cc', 'ai', 'ws', 'to', 'fm', 'gg', 'sh', 'ly', 'id', 'in'}


def region_of(tld):
    '''
    Given a tld/zone label (e.g. 'ru', 'co.uk', 'com', 'android'), return
    (country, region).  Unknown/app-specific zones return ('', 'Other / unknown').
    '''
    if not tld:
        return ('', 'Other / unknown')
    tld = tld.lower().lstrip('.')
    # multi-part suffix like co.uk -> use the country part
    if '.' in tld:
        tld = tld.split('.')[-1]
    if tld in CCTLD:
        country, region = CCTLD[tld]
        if tld in GENERIC_CCTLD:
            region = f'{region} (often generic)'
        return (country, region)
    if tld in GTLD:
        return ('', 'Generic (gTLD)')
    return ('', 'Other / unknown')


def country_of(tld):
    return region_of(tld)[0]


def is_country_zone(tld):
    tld = (tld or '').lower().lstrip('.').split('.')[-1]
    return tld in CCTLD
