# by TheTechromancer
# DFIR enhancement: added phone + service(URL) fields for stealer-log / ULP data

import base64
import hashlib
from .util import *
from .errors import *
from . import validation



class Account():

    # cut down on memory usage by not using a dictionary
    __slots__ = ['_id', '_email', 'domain', 'username', 'password', 'hashes', 'misc', 'sources', 'phone', 'service']

    # max length for email, domain, username, password, phone, service
    max_length_1 = 127
    # max length for hash, misc
    max_length_2 = 1023

    # translation table to strip bad characters from username
    strip_from_username = str.maketrans('', '', "'\\")

    def __init__(self, email='', username='', password='', hashes=[], misc='', sources=[], phone='', service=''):

        # validate types
        if type(hashes) == str:
            hashes = [hashes]
        if type(sources) in (str, int):
            sources = [int(s)]
        else:
            sources = [int(s) for s in sources]

        # sanitize
        email    = validation.clean_utf(email)
        username = validation.clean_utf(username)
        password = validation.clean_utf(password)
        hashes   = [validation.clean_utf(h) for h in hashes]
        misc     = validation.clean_utf(misc)

        # initialize variables
        self._id = ''
        self._email = ''
        self.username = ''
        self.password = ''
        self.misc = ''
        self.hashes = []
        self.sources = sources
        self.phone = ''
        self.service = ''

        try:
            self.set_email(email)
        except AccountCreationError:
            # keep going - the account may be valid on username/phone alone
            self._email = ''
            self.domain = ''

        # sanitize username
        self.username = username.strip().translate(self.strip_from_username)[:self.max_length_1]

        # truncate values to max length
        self.misc = misc[:self.max_length_2]
        self.password = password[:self.max_length_1]
        for h in hashes:
            if h not in self.hashes:
                self.hashes.append(h[:self.max_length_2])

        # phone: store bare normalized digits (country code preserved)
        if phone:
            self.phone = validation.normalize_phone(phone)[:self.max_length_1]

        # service: normalized hostname of the breached site (ULP "URL" field)
        if service:
            self.service = validation.extract_host(service)[:self.max_length_1]

        # if username is an email address, do the needful
        if not self._email:
            if validation.is_email(self.username):
                self.set_email(self.username)
                self.username = ''

        # if the username is actually a phone number and we have no phone yet, route it
        if not self.phone and self.username and validation.is_phone(self.username):
            normalized = validation.normalize_phone(self.username)
            if normalized:
                self.phone = normalized[:self.max_length_1]
                self.username = ''

        # if password is hashed, put it in hash field
        if self.password:
            if validation.is_hash(self.password):
                self.hashes.append(self.password)
                self.password = ''

        # if the password is super long, put it in misc
        if not self.misc and len(self.password) >= self.max_length_1:
            self.password, self.misc = '', self.password

        # An account is worth keeping if:
        #   - we have an email (useful even by itself, for OSINT / leak membership), OR
        #   - we have a username or phone AND some secret (password/hash/misc) or service context
        has_secret = bool(self.password or self.misc or self.hashes)
        if self._email:
            keep = True
        elif (self.username or self.phone) and (has_secret or self.service):
            keep = True
        elif self.hashes:
            # a hash with no identity is still useful reference data
            # (e.g. a hashcat potfile line: <hash>:<cracked plaintext>)
            keep = True
        else:
            keep = False

        if not keep:
            raise AccountCreationError(f'Not enough information to create account:\n{str(self)[:64]}')


    @property
    def document(self, id_only=False):
        '''
        Returns dictionary in database format
        '''

        doc = dict()

        try:
            doc['_id'] = self.id
            if not id_only:
                if self._email:
                    doc['e'] = self._email
                if self.username:
                    doc['u'] = self.username
                if self.password:
                    doc['p'] = self.password
                if self.hashes:
                    doc['h'] = self.hashes
                if self.misc:
                    doc['m'] = self.misc
                if self.phone:
                    doc['t'] = self.phone
                if self.service:
                    # stored reversed so service/zone queries can use a prefix index
                    # (mirrors how the email domain is reversed inside _id)
                    doc['v'] = self.service[::-1]
        except ValueError:
            raise AccountCreationError(f'[!] Error formatting {str(self.bytes)[:64]}')

        return doc


    @property
    def json(self):
        '''
        Returns dictionary in human-friendly format
        '''
        j = dict()
        j['e'] = self.email
        j['u'] = self.username
        j['p'] = self.password
        j['h'] = self.hashes
        j['m'] = self.misc
        j['t'] = self.phone
        j['v'] = self.service
        j['s'] = self.sources
        return j



    def set_email(self, email):

        self._email = ''
        new_email = validation.clean_email(email)[-self.max_length_1:]
        if not validation.is_email(new_email):
            raise AccountCreationError(f'Invalid email: {new_email}')

        self._email, self.domain = new_email.split('@', 1)
        self._email, self.domain = self.handle_special_email_cases(self._email, self.domain)



    @staticmethod
    def handle_special_email_cases(email, domain):
        '''
        Handles special gmail email address tricks, etc.
        '''

        # handle gmail
        if domain in ['gmail.com', 'googlemail.com']:
            return (email.replace('.', '').split('+')[0], domain)
        else:
            return (email, domain)



    @classmethod
    def from_document(cls, document):

        _email = document.get('e')
        _id = document.get('_id', '')
        domain = _id.split('|')[0]
        if _email and domain:
            email = _email + '@' + domain[::-1]
        else:
            email = ''
        username = document.get('u', '')
        password = document.get('p', '')
        hashes = document.get('h', [])
        misc = document.get('m', '')
        phone = document.get('t', '')
        # service stored reversed
        service = document.get('v', '')
        if service:
            service = service[::-1]
        sources = document.get('s', [])
        return cls(email=email, username=username, password=password, hashes=hashes,
                   misc=misc, sources=sources, phone=phone, service=service)


    @property
    def bytes(self, delimiter=b'\x00'):

        return delimiter.join(
            x.encode('utf-8', errors='ignore') for x in
            [self.email, self.username, self.password, self.formatted_hashes, self.misc, self.phone, self.service]
        )


    @property
    def id(self):
        '''
        hacky compound domain-->email index
        first 6 bytes of _id after the domain are a hash of the email
        '''

        if not self._id:

            if self._email:
                # _id begins with reversed domain
                domain_chunk = self.domain[::-1]
                email_hash = base64.b64encode(hashlib.sha1(self._email.encode()).digest()[:6]).decode()
                account_hash = email_hash + base64.b64encode(hashlib.sha1(self.bytes).digest()[:6]).decode()
            else:
                account_hash = base64.b64encode(hashlib.sha1(self.bytes).digest()[:12]).decode()
                domain_chunk = ''

            self._id = '|'.join([domain_chunk, account_hash])

        return self._id


    @property
    def formatted_hashes(self):

        hashes = list(set(self.hashes))
        hashes.sort(key=lambda x: len(x))
        return '|'.join(hashes)


    @property
    def email(self):

        if self._email and self.domain:
            return self._email + '@' + self.domain
        else:
            return ''


    def __repr__(self):

        if self.username:
            return self.username
        elif self.email:
            return self.email
        elif self.phone:
            return self.phone
        else:
            return self.service


    def __eq__(self, other):

        if hash(self) == hash(other):
            return True
        else:
            return False


    def __hash__(self):

        return hash(self.bytes)


    def __str__(self):

        return ':'.join([self.email, self.username, self.password, self.formatted_hashes,
                         self.misc, self.phone, self.service])


    def __iter__(self):

        for k,v in self.document.items():
            yield (k,v)
