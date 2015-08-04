'''

Classes used to retrieve and parse crossdomain.xml files

'''

import logging
import requests
import tldextract

from whois import whois
from whois.parser import PywhoisError
from netaddr import valid_ipv4
from urlparse import urlparse
from xml.etree.ElementTree import ParseError

try:
    import defusedxml.cElementTree as ET
except ImportError:
    import defusedxml.ElementTree as ET


class CrossDomainPolicy(object):

    ''' This object represents a domains crossdomain.xml '''

    def __init__(self, xml_doc, logging_channel='CrossDomain'):
        self._dom = ET.fromstring(xml_doc)
        self.logger = logging.getLogger(logging_channel)

    @property
    def allow_access_from(self):
        ''' Returns domains lists in allow-access-from '''
        elems = self._dom.findall(".//allow-access-from")
        return [el.get('domain') for el in elems]

    @property
    def allow_access_from_identity(self):
        elems = self._dom.findall(".//allow-access-from-identity")
        return [el.get('signatory') for el in elems]

    @property
    def allow_http_request_headers_from(self):
        elems = self._dom.findall(".//allow-http-request-headers-from")
        return [(el.get('domain'), el.get('headers')) for el in elems]

    def __iter__(self):
        ''' Iterates over allow-access-from domains '''
        for domain in self.allow_access_from:
            self.logger.info("Parsing allow-access-from %s" % (
                domain
            ))
            yield domain


class CrossDomainScanner(object):

    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
    }

    def __init__(self, domains, http_timeout=3, logging_channel='CrossDomain'):
        self.domains = domains
        self.results = {}
        self.wildcards = []
        self._cache = {}
        self.http_timeout = float(http_timeout)
        self.logger = logging.getLogger(logging_channel)

    def start(self):
        ''' Start scanning all of the domains '''
        for domain in self.domains:
            try:
                self.get_crossdomain(domain)
            except requests.exceptions.ConnectionError:
                self.logger.warn("Could not connect to: %s" % domain)
            except KeyboardInterrupt:
                raise
            except:
                self.logger.exception("CrossDomainScanner raised an exception")

    def get_crossdomain(self, domain):
        '''
        Grab the crossdomain.xml, if the resp is OK then try to parse it
        '''
        try:
            url = "http://%s/crossdomain.xml" % domain
            self.logger.info("Requesting: %s" % url)
            resp = requests.get(url,
                                timeout=self.http_timeout,
                                headers=self.headers)
            if resp.ok and len(resp.text):
                self.analyze_policy(domain, resp)
        except requests.exceptions.Timeout:
            self.logger.warn("Timeout requesting crossdomain.xml from %s" % (
                domain
            ))
        except KeyboardInterrupt:
            raise
        except (ParseError, UnicodeEncodeError):
            self.logger.exception("Could not parse respose from %s as XML" % (
                domain,
            ))

    def analyze_policy(self, domain, resp):
        ''' Analyze the domains crossdomain.xml file '''
        for entry in CrossDomainPolicy(resp.text):
            # Skip the IP Addresses
            if self._is_ip(entry):
                continue
            # Skip the duplicates
            tld = self._parse_tld(entry)
            if tld in self._cache:
                continue
            else:
                self._cache[tld] = True
            self.analyze_tld(domain, tld)

    def analyze_tld(self, domain, tld):
        ''' Given a TLD we attempt to figure out if it poses a risk '''
        if tld == "*":
            self.logger.critical("%s's crossdomain.xml contains a root wildcard" % (
                domain
            ))
            self.wildcards.append(domain)
        elif self.is_expired(tld):
            self.logger.critical("%s's crossdomain.xml contains expired domain %s" % (
                domain, tld
            ))
            if domain not in self.results:
                self.results[domain] = []
            self.results[domain].append(tld)

    def is_expired(self, domain):
        ''' Blindly grabbing PywhoisError isn't ideal but works '''
        try:
            whois(domain)
            return False
        except PywhoisError:
            return True

    def _is_ip(self, domain):
        '''
        This extra parsing handles a variety of edge cases such as:
            - http://192.168.1.1
            - http://192.168.1.1:81
            - 192.168.1.1:81
        '''
        if valid_ipv4(domain):
            return True
        if urlparse(domain).scheme != '':
            domain = urlparse(domain).netloc
        if ':' in domain:
            domain = domain[:domain.rindex(':')]
        return valid_ipv4(domain)

    def _parse_tld(self, url):
        ''' Little extra parsing to accurately return a TLD string '''
        tld = tldextract.extract(url)
        if tld.suffix == '':
            return tld.domain
        else:
            return "%s.%s" % (tld.domain, tld.suffix)
