#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: dns_firewall
   :synopsis: Local DNS firewall

"""

# Released under AGPLv3+ license, see LICENSE

from fnmatch import fnmatch
from gevent.server import DatagramServer
from psutil._compat import lru_cache
from setproctitle import setproctitle
import argparse
import dpkt.dns
import logging
import psutil
import socket
import struct
import yaml

cfg = {}

log = logging.getLogger(__name__)

color_map = dict(
    accept=32,  # green
    drop=31,  # red
    nxdomain=31,  # red
    unmanaged=30,
    default=33,  # yellow, used by "return"
)


def setup_logging():
    log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s %(levelname)s %(message)s')
    ch.setFormatter(formatter)
    log.addHandler(ch)


def color(action):
    col = color_map.get(action, color_map['default'])
    return "\033[0;%dm%s\033[1;0m" % (col, action)


def query_resolver(server, port, querydata):
    """Send the query to an external resolver
    """

    if cfg['udp_mode']:
        sendbuf = querydata
    else:
        # length
        Buflen = struct.pack('!h', len(querydata))
        sendbuf = Buflen + querydata

    data = None
    try:
        if not cfg['udp_mode']:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # set socket timeout
        s.settimeout(cfg['socket_timeout'])
        s.connect((server, int(port)))
        s.send(sendbuf)
        data = s.recv(2048)
    except Exception as e:
        log.info('[ERROR] query_resolver: %s' % e.message)
    finally:
        if s:
            s.close()
        return data


def extract_domain(s):
    """Extract domain
    """
    domain = ''
    i = 0
    length = struct.unpack('!B', s[0:1])[0]

    while length != 0:
        i += 1
        domain += s[i:i + length]
        i += length
        length = struct.unpack('!B', s[i:i + 1])[0]
        if length != 0:
            domain += '.'

    return domain


def check_dns_packet(data, q_type):

    if len(data) < 12:
        return False

    if cfg['udp_mode']:
        flags = data[2:4]
    else:
        flags = data[4:6]

    if q_type == 0x0001:

        ip_len = data[-6:-4]
        answer_class = data[-12:-10]
        answer_type = data[-14:-12]

        test = (ip_len == '\x00\x04' and answer_class == '\x00\x01' and
                answer_type == '\x00\x01')

        if not test:
            return False

    reply_code = struct.unpack('>h', flags)[0] & 0x000F
    return reply_code == 0


def fetch_pid(port):
    assert isinstance(port, int)
    for c in psutil.net_connections(kind='udp'):
        # if not c.raddr and c.laddr == ('0.0.0.0', port):
        if c.raddr in ((), ('127.0.0.1', 53)) \
            and c.laddr in (('0.0.0.0', port), ('127.0.0.1', port)):
            return c.pid

    log.error('No pid found %d', port)
    for c in psutil.net_connections(kind='udp'):
        if c.pid:
            name = fetch_process_name(c.pid)
            log.error('repr %r name %s', c, name)
        else:
            log.error('repr %r', c)


def fetch_process_name(pid):
    fname = "/proc/%d/cmdline" % pid
    with open(fname) as f:
        return f.read().split('\0', 1)[0]


@lru_cache(maxsize=10, typed=True)
def identify_caller(address):
    ip_address, port = address
    pid = fetch_pid(port)
    if pid is None:
        return

    return fetch_process_name(pid)


def resolve_over_tor(name):
    """Resolve using a local Tor instance"""
    # Send Tor SOCKS RESOLVE request.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks_addr = (cfg['tor_socks_ipaddr'], cfg['tor_socks_port'])
    s.connect(socks_addr)
    buf = struct.pack('>BBHI', 4, 0xF0, 0, 1) + '\x00%s\x00' % name
    s.send(buf)
    v, stat, port, ipaddr = struct.unpack('>BBH4s', s.recv(1024))
    ipaddr = socket.inet_ntoa(ipaddr)

    if stat == 90:
        return ipaddr

    log.debug("Failed resolution over Tor")


class DNSServer(DatagramServer):

    def handle(self, querydata, address):
        client_program_name = identify_caller(address)
        self._handle_query(client_program_name, querydata, address)

    def _forward_query_to_resolver(self, querydata, src):
        """Forward DNS query to resolvers"""
        key = querydata[2:].encode('hex')
        for item in cfg['udp_dns_servers']:
            ipaddr, port = item.split(':')

            response = query_resolver(ipaddr, port, querydata)
            if response is None:
                # or not check_dns_packet(response, q_type):
                continue

            if self.lru_cache is not None:
                self.lru_cache[key] = response

            self.socket.sendto(response, src)
            return

    def _decide_action(self, client_program_name, query):
        """Decide action"""
        # FIXME: clean this code up
        if query.qr == dpkt.dns.DNS_Q and len(query.qd) == 1 \
            and len(query.an) == 0 and len(query.ns) == 0:
            q = query.qd[0]
        else:
            return 'transparent'

        q_domain = q.name
        q_type = q.type

        if q_type not in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
            return 'transparent'

        if q.cls != dpkt.dns.DNS_IN:
            return 'transparent'

        rules = cfg['filtering']
        filtering_rules = rules.get(client_program_name, []) + rules['general']

        for domain_filter, action in filtering_rules:
            if not fnmatch(q_domain, domain_filter):
                continue

            if self.tray_icon:
                self.tray_icon.add_log_message(
                    client_program_name,
                    q_domain,
                    domain_filter,
                    action
                )
            log.debug("%r %r is matching %r -> %s" % (client_program_name,
                q_domain, domain_filter, color(action)))
            return action


    def _return_nxdomain(self, query, src):
        """Return NXDOMAIN"""
        ans = dpkt.dns.DNS()
        ans.op = dpkt.dns.DNS_RA
        ans.rcode = dpkt.dns.DNS_RCODE_NXDOMAIN
        ans.qr = dpkt.dns.DNS_R
        ans.id = query.id
        ans.qd.append(query.qd[0])
        self.socket.sendto(ans.pack(), src)

    def _return_ipaddr(self, query, ip_addr, src, ttl=600):
        """Return a given ipaddr"""
        ans = dpkt.dns.DNS()
        ans.op = dpkt.dns.DNS_RA
        ans.rcode = dpkt.dns.DNS_RCODE_NOERR
        ans.qr = dpkt.dns.DNS_R
        ans.id = query.id
        ans.qd.append(query.qd[0])

        arr = dpkt.dns.DNS.RR()
        arr.cls = dpkt.dns.DNS_IN
        arr.type = dpkt.dns.DNS_A
        arr.name = query.qd[0].name
        arr.ttl = ttl
        arr.ip = socket.inet_aton(ip_addr)
        ans.an.append(arr)

        self.socket.sendto(ans.pack(), src)

    def _handle_query(self, client_program_name, querydata, src):
        """Handle incoming query, return response
        """
        query = dpkt.dns.DNS(querydata)
        action = self._decide_action(client_program_name, query)

        if action == 'accept':
            # forward query, use caching
            if cfg['use_tor']:
                ip_addr = resolve_over_tor(query.qd[0].name)
                if ip_addr:
                    self._return_ipaddr(query, ip_addr, src)

            else:
                self._forward_query_to_resolver(querydata, src)

        elif action == 'nxdomain':
            self._return_nxdomain(query, src)

        elif action.startswith('return '):
            # return a fixed IP address
            ip_addr = action[7:].strip()
            self._return_ipaddr(query, ip_addr, src)

        elif action == 'drop':
            # simply drop the query
            return





def start_dns_server(cfg, tray_icon):
    server = DNSServer('%s:%s' % (cfg["host"], cfg["port"]))
    if cfg['enable_lru_cache']:
        # FIXME: implement caching
        server.lru_cache = {}

    server.tray_icon = tray_icon
    server.serve_forever()


def start_tray_icon():
    from ui import TrayIcon
    tray_icon = TrayIcon()
    tray_icon.start()
    return tray_icon


def main():
    global cfg

    setproctitle('dnsfirewall')

    setup_logging()

    parser = argparse.ArgumentParser(description='TCP DNS Proxy')
    parser.add_argument(dest='config_fname', type=argparse.FileType('r'),
                        help='config file')
    parser.add_argument('--tray', help='Enable tray icon', action='store_true',
                        default=False)
    args = parser.parse_args()

    cfg = yaml.load(args.config_fname)

    if args.tray:
        tray_icon = start_tray_icon()
    else:
        tray_icon = None

    log.info("DNS servers: %s", ' '.join(cfg['udp_dns_servers']))
    log.info("Query timeout: %f", cfg['socket_timeout'])
    log.info("Enable cache: %r", cfg['enable_lru_cache'])

    start_dns_server(cfg, tray_icon)


if __name__ == "__main__":
    main()
