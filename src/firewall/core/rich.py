# -*- coding: utf-8 -*-
#
# Copyright (C) 2013-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

__all__ = [ "Source", "Destination", "Service", "Port",
            "Protocol", "Masquerade", "IcmpBlock",
            "Rich_IcmpType",
            "SourcePort", "Rich_ForwardPort", "Rich_Log", "Rich_NFLog",
            "Rich_Accept", "Rich_Reject", "Rich_Drop", "Rich_Mark",
            "Rich_Audit", "Rich_Limit", "Rich_Rule", "Rich_Tcp_Mss_Clamp",
            "AddressFlag", "InversionFlag" ]

from dataclasses import dataclass
from enum import IntFlag

from firewall import functions
from firewall.core.ipset import check_ipset_name
from firewall.core.base import REJECT_TYPES
from firewall import errors
from firewall.errors import FirewallError


class AddressFlag(IntFlag):
    NONE = 0
    INTERFACE = 1 << 1
    MAC = 1 << 2
    IPV4 = 1 << 3
    IPV6 = 1 << 4
    ADDRESS = IPV4 | IPV6
    IPSET = 1 << 5
    INVERTED = 1 << 6


class InversionFlag(IntFlag):
    NONE = 0
    SOURCE = 1 << 1
    DESTINATION = 1 << 2
    SERVICE = 1 << 3
    PORT = 1 << 4
    PROTOCOL = 1 << 5
    SOURCE_PORT = 1 << 6
    ICMP_BLOCK = 1 << 7

    @classmethod
    def get(cls, flag: str):
        return cls[flag.upper().replace("-", "_")]


@dataclass
class Source:
    address: str
    flags: AddressFlag

    def __post_init__(self) -> None:
        if self.flags & AddressFlag.MAC:
            self.address = self.address.upper()

    def __str__(self) -> str:
        ret = f'source{(" NOT" if self.flags & AddressFlag.INVERTED else "")}'
        if self.flags & AddressFlag.ADDRESS:
            return f'{ret} address="{self.address}"'
        elif self.flags & AddressFlag.MAC:
            return f'{ret} mac="{self.address}"'
        elif self.flags & AddressFlag.IPSET:
            return f'{ret} ipset="{self.address}"'
        raise FirewallError(errors.INVALID_RULE,
                            "no address, mac and ipset")

@dataclass
class Destination:
    address: str
    flags: AddressFlag

    def __str__(self) -> str:
        ret = f'destination{(" NOT" if self.flags & AddressFlag.INVERTED else "")}'
        if self.flags & AddressFlag.ADDRESS:
            return f'{ret} address="{self.address}"'
        elif self.flags & AddressFlag.IPSET:
            return f'{ret} ipset="{self.address}"'
        raise FirewallError(errors.INVALID_RULE,
                            "no address and ipset")

@dataclass
class Service:
    name: str
    invert: bool = False

    def __str__(self) -> str:
        return f'service{(" NOT" if self.invert else "")} name="{self.name}"'

@dataclass
class Port:
    port: str
    protocol: str
    invert: bool = False

    def __str__(self) -> str:
        return f'port{(" NOT" if self.invert else "")} port="{self.port}" protocol="{self.protocol}"'

@dataclass
class SourcePort:
    port: str
    protocol: str
    invert: bool = False

    def __str__(self) -> str:
        return f'source-port{(" NOT" if self.invert else "")} port="{self.port}" protocol="{self.protocol}"'

@dataclass
class Protocol:
    value: str
    invert: bool = False

    def __str__(self) -> str:
        return f'protocol{(" NOT" if self.invert else "")} value="{self.value}"'

@dataclass
class Masquerade:
    def __str__(self) -> str:
        return 'masquerade'

@dataclass
class IcmpBlock:
    name: str
    invert: bool = False

    def __str__(self) -> str:
        return f'icmp-block{(" NOT" if self.invert else "")} name="{self.name}"'

class Rich_IcmpType(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'icmp-type name="%s"' % (self.name)

class Rich_Tcp_Mss_Clamp(object):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return 'tcp-mss-clamp value="%s"' % (self.value)

class Rich_ForwardPort(object):
    def __init__(self, port, protocol, to_port, to_address):
        self.port = port
        self.protocol = protocol
        self.to_port = to_port
        self.to_address = to_address
        # replace None with "" in to_port and/or to_address
        if self.to_port is None:
            self.to_port = ""
        if self.to_address is None:
            self.to_address = ""

    def __str__(self):
        return 'forward-port port="%s" protocol="%s"%s%s' % \
            (self.port, self.protocol,
             ' to-port="%s"' % self.to_port if self.to_port != "" else '',
             ' to-addr="%s"' % self.to_address if self.to_address != "" else '')

class Rich_Log(object):
    def __init__(self, prefix=None, level=None, limit=None):
        #TODO check default level in iptables
        self.prefix = prefix
        self.level = level
        self.limit = limit

    def __str__(self):
        return 'log%s%s%s' % \
            (' prefix="%s"' % (self.prefix) if self.prefix else "",
             ' level="%s"' % (self.level) if self.level else "",
             " %s" % self.limit if self.limit else "")

    def check(self):
        if self.prefix and len(self.prefix) > 127:
            raise FirewallError(errors.INVALID_LOG_PREFIX, "maximum accepted length of 'prefix' is 127.")

        if self.level and \
               self.level not in [ "emerg", "alert", "crit", "error",
                                       "warning", "notice", "info", "debug" ]:
            raise FirewallError(errors.INVALID_LOG_LEVEL, self.level)

        if self.limit is not None:
            self.limit.check()

class Rich_NFLog(object):
    def __init__(self, group=None, prefix=None, queue_size=None, limit=None):
        self.group = group
        self.prefix = prefix
        self.threshold = queue_size
        self.limit = limit

    def __str__(self):
        return 'nflog%s%s%s%s' % \
            (' group="%s"' % (self.group) if self.group else "",
             ' prefix="%s"' % (self.prefix) if self.prefix else "",
             ' queue-size="%s"' % (self.threshold) if self.threshold else "",
             " %s" % self.limit if self.limit else "")

    def check(self):
        if self.group and not functions.checkUINT16(self.group):
            raise FirewallError(errors.INVALID_NFLOG_GROUP, "nflog 'group' must be an integer between 0 and 65535.")

        if self.prefix and len(self.prefix) > 127:
            raise FirewallError(errors.INVALID_LOG_PREFIX, "maximum accepted length of 'prefix' is 127.")

        if self.threshold and not functions.checkUINT16(self.threshold):
            raise FirewallError(errors.INVALID_NFLOG_QUEUE, "nflog 'queue-size' must be an integer between 0 and 65535.")

        if self.limit is not None:
            self.limit.check()

class Rich_Audit(object):
    def __init__(self, limit=None):
        #TODO check default level in iptables
        self.limit = limit

    def __str__(self):
        return 'audit%s' % (" %s" % self.limit if self.limit else "")

class Rich_Accept(object):
    def __init__(self, limit=None):
        self.limit = limit

    def __str__(self):
        return "accept%s" % (" %s" % self.limit if self.limit else "")

class Rich_Reject(object):
    def __init__(self, _type=None, limit=None):
        self.type = _type
        self.limit = limit

    def __str__(self):
        return "reject%s%s" % (' type="%s"' % self.type if self.type else "",
                               " %s" % self.limit if self.limit else "")

    def check(self, family):
        if self.type:
            if not family:
                raise FirewallError(errors.INVALID_RULE, "When using reject type you must specify also rule family.")
            if family in ['ipv4', 'ipv6'] and \
               self.type not in REJECT_TYPES[family]:
                valid_types = ", ".join(REJECT_TYPES[family])
                raise FirewallError(errors.INVALID_RULE, "Wrong reject type %s.\nUse one of: %s." % (self.type, valid_types))

class Rich_Drop(Rich_Accept):
    def __str__(self):
        return "drop%s" % (" %s" % self.limit if self.limit else "")


class Rich_Mark(object):
    def __init__(self, _set, limit=None):
        self.set = _set
        self.limit = limit

    def __str__(self):
        return "mark set=%s%s" % (self.set,
                                  " %s" % self.limit if self.limit else "")

    def check(self):
        if self.set is not None:
            x = self.set
        else:
            raise FirewallError(errors.INVALID_MARK, "no value set")

        if "/" in x:
            splits = x.split("/")
            if len(splits) != 2:
                raise FirewallError(errors.INVALID_MARK, x)
            if not functions.checkUINT32(splits[0]) or \
               not functions.checkUINT32(splits[1]):
                # value and mask are uint32
                raise FirewallError(errors.INVALID_MARK, x)
        else:
            if not functions.checkUINT32(x):
                # value is uint32
                raise FirewallError(errors.INVALID_MARK, x)

class Rich_Limit(object):
    def __init__(self, value):
        self.value = value
        if "/" in self.value:
            splits = self.value.split("/")
            if len(splits) == 2 and \
               splits[1] in [ "second", "minute", "hour", "day" ]:
                self.value = "%s/%s" % (splits[0], splits[1][:1])

    def check(self):
        splits = None
        if "/" in self.value:
            splits = self.value.split("/")
        if not splits or len(splits) != 2:
            raise FirewallError(errors.INVALID_LIMIT, self.value)
        (rate, duration) = splits
        try:
            rate = int(rate)
        except:
            raise FirewallError(errors.INVALID_LIMIT, self.value)

        if rate < 1 or duration not in [ "s", "m", "h", "d" ]:
            raise FirewallError(errors.INVALID_LIMIT, self.value)

        mult = 1
        if duration == "s":
            mult = 1
        elif duration == "m":
            mult = 60
        elif duration == "h":
            mult = 60*60
        elif duration == "d":
            mult = 24*60*60

        if 10000 * mult / rate == 0:
            raise FirewallError(errors.INVALID_LIMIT,
                                "%s too fast" % self.value)

        if rate == 1 and duration == "d":
            # iptables (v1.4.21) doesn't accept 1/d
            raise FirewallError(errors.INVALID_LIMIT,
                                "%s too slow" % self.value)

    def __str__(self):
        return 'limit value="%s"' % (self.value)

    def command(self):
        return ''

class Rich_Rule(object):
    priority_min = -32768
    priority_max =  32767

    def __init__(self, family=None, rule_str=None, priority=0):
        if family is not None:
            self.family = str(family)
        else:
            self.family = None

        self.priority = priority
        self.source = None
        self.destination = None
        self.element = None
        self.log = None
        self.audit = None
        self.action = None

        if rule_str:
            self._import_from_string(rule_str)

    def _lexer(self, rule_str):
        """ Lexical analysis """
        tokens = []

        for r in functions.splitArgs(rule_str):
            if "=" in r:
                attr = r.split('=')
                if len(attr) != 2 or not attr[0] or not attr[1]:
                    raise FirewallError(errors.INVALID_RULE,
                                        'internal error in _lexer(): %s' % r)
                tokens.append({'attr_name':attr[0], 'attr_value':attr[1]})
            else:
                tokens.append({'element':r})
        tokens.append({'element':'EOL'})

        return tokens

    def _import_from_string(self, rule_str):
        if not rule_str:
            raise FirewallError(errors.INVALID_RULE, 'empty rule')

        rule_str = functions.stripNonPrintableCharacters(rule_str)

        self.priority = 0
        self.family = None
        self.source = None
        self.destination = None
        self.element = None
        self.log = None
        self.audit = None
        self.action = None

        tokens = self._lexer(rule_str)
        if tokens and tokens[0].get('element')  == 'EOL':
            raise FirewallError(errors.INVALID_RULE, 'empty rule')

        attrs = {}                      # attributes of elements
        inversions = InversionFlag.NONE # inverted element flags
        flags = AddressFlag.NONE           # address flags
        in_elements = []                # stack with elements we are in
        index = 0                       # index into tokens
        while not (tokens[index].get('element')  == 'EOL' and in_elements == ['rule']):
            element = tokens[index].get('element')
            attr_name = tokens[index].get('attr_name')
            attr_value = tokens[index].get('attr_value')
            #print ("in_elements: ", in_elements)
            #print ("index: %s, element: %s, attribute: %s=%s" % (index, element, attr_name, attr_value))
            if attr_name:     # attribute
                if attr_name not in ['priority', 'family', 'address', 'mac', 'ipset',
                                     'invert', 'value',
                                     'port', 'protocol', 'to-port', 'to-addr',
                                     'name', 'group', 'prefix', 'level', 'queue-size', 'type',
                                     'set']:
                    raise FirewallError(errors.INVALID_RULE, "bad attribute '%s'" % attr_name)
            else:             # element
                if element in ['rule', 'source', 'destination', 'protocol',
                               'service', 'port', 'icmp-block', 'icmp-type', 'masquerade',
                               'forward-port', 'source-port', 'log', 'nflog', 'audit',
                               'accept', 'drop', 'reject', 'mark', 'limit', 'not', 'NOT', 'EOL', 'tcp-mss-clamp']:
                    if element == 'source' and self.source:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'source' element")
                    elif element == 'destination' and self.destination:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'destination' element")
                    elif element in ['protocol', 'service', 'port',
                                     'icmp-block', 'icmp-type',
                                     'masquerade', 'forward-port',
                                     'source-port'] and self.element:
                        raise FirewallError(errors.INVALID_RULE, "more than one element. There cannot be both '%s' and '%s' in one rule." % (element, self.element))
                    elif element in ['log', 'nflog'] and self.log:
                        raise FirewallError(errors.INVALID_RULE, "more than one logging element")
                    elif element == 'audit' and self.audit:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'audit' element")
                    elif element in ['accept', 'drop', 'reject', 'mark'] and self.action:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'action' element. There cannot be both '%s' and '%s' in one rule." % (element, self.action))
                else:
                    raise FirewallError(errors.INVALID_RULE, "unknown element %s" % element)

            in_element = in_elements[len(in_elements)-1] if len(in_elements) > 0 else ''

            if in_element == '':
                if not element and attr_name:
                    if attr_name == 'family':
                        raise FirewallError(errors.INVALID_RULE, "'family' outside of rule. Use 'rule family=...'.")
                    elif attr_name == 'priority':
                        raise FirewallError(errors.INVALID_RULE, "'priority' outside of rule. Use 'rule priority=...'.")
                    else:
                        raise FirewallError(errors.INVALID_RULE, "'%s' outside of any element. Use 'rule <element> %s= ...'." % (attr_name, attr_name))
                elif 'rule' not in element:
                    raise FirewallError(errors.INVALID_RULE, "'%s' outside of rule. Use 'rule ... %s ...'." % (element, element))
                else:
                    in_elements.append('rule') # push into stack
            elif in_element == 'rule':
                if attr_name == 'family':
                    if attr_value not in ['ipv4', 'ipv6']:
                        raise FirewallError(errors.INVALID_RULE, "'family' attribute cannot have '%s' value. Use 'ipv4' or 'ipv6' instead." % attr_value)
                    self.family = attr_value
                elif attr_name == 'priority':
                    try:
                        self.priority = int(attr_value)
                    except ValueError:
                        raise FirewallError(errors.INVALID_PRIORITY, "invalid 'priority' attribute value '%s'." % attr_value)
                elif attr_name:
                    if attr_name == 'protocol':
                        err_msg = "wrong 'protocol' usage. Use either 'rule protocol value=...' or  'rule [forward-]port protocol=...'."
                    else:
                        err_msg = "attribute '%s' outside of any element. Use 'rule <element> %s= ...'." % (attr_name, attr_name)
                    raise FirewallError(errors.INVALID_RULE, err_msg)
                else:
                    in_elements.append(element) # push into stack
            elif in_element == 'source':
                if attr_name in ['address', 'mac', 'ipset']:
                    flags |= AddressFlag[attr_name.upper()]
                    attrs['address'] = attr_value
                elif attr_name == 'invert':
                    if functions.parse_boolean(attr_value):
                        inversions |= InversionFlag.SOURCE
                    else:
                        inversions &= ~InversionFlag.SOURCE
                elif element in ['not', 'NOT']:
                    if tokens[index + 1].get('attr_name') in ['address', 'mac', 'ipset']:
                        inversions |= InversionFlag.SOURCE
                    elif tokens[index + 1].get('element') in ['destination', 'port', 'protocol', 'service', 'source-port']:
                        inversions |= InversionFlag.get(tokens[index + 1]['element'])
                else:
                    try:
                        if inversions & InversionFlag.SOURCE:
                            flags |= AddressFlag.INVERTED
                        self.source = Source(attrs['address'], flags)
                    except KeyError as exc:
                        raise FirewallError(errors.INVALID_RULE,
                            "no address, mac and ipset") from exc
                    in_elements.pop() # source
                    attrs.clear()
                    flags = AddressFlag.NONE
                    index = index -1 # return token to input
            elif in_element == 'destination':
                if attr_name in ['address', 'ipset']:
                    flags |= AddressFlag[attr_name.upper()]
                    attrs['address'] = attr_value
                elif attr_name == 'invert':
                    if functions.parse_boolean(attr_value):
                        inversions |= InversionFlag.DESTINATION
                    else:
                        inversions &= ~InversionFlag.DESTINATION
                elif element in ['not', 'NOT']:
                    if tokens[index + 1].get('attr_name') in ['address', 'ipset']:
                        inversions |= InversionFlag.DESTINATION
                    elif tokens[index + 1].get('element') in ['port', 'protocol', 'service', 'source', 'source-port']:
                        inversions |= InversionFlag.get(tokens[index + 1]['element'])
                else:
                    try:
                        if inversions & InversionFlag.DESTINATION:
                            flags |= AddressFlag.INVERTED
                        self.destination = Destination(attrs['address'], flags)
                    except KeyError as exc:
                        raise FirewallError(errors.INVALID_RULE,
                            "no address and ipset") from exc
                    in_elements.pop() # destination
                    attrs.clear()
                    flags = AddressFlag.NONE
                    index = index -1 # return token to input
            elif in_element == 'protocol':
                if attr_name == 'value':
                    attrs['value'] = attr_value
                elif attr_name == 'invert':
                    if functions.parse_boolean(attr_value):
                        inversions |= InversionFlag.PROTOCOL
                    else:
                        inversions &= ~InversionFlag.PROTOCOL
                elif element in ['not', 'NOT']:
                    if tokens[index + 1].get('attr_name') == 'value':
                        inversions |= InversionFlag.PROTOCOL
                    elif tokens[index + 1].get('element') in ['destination', 'service', 'source', 'source-port']:
                        inversions |= InversionFlag.get(tokens[index + 1]['element'])
                else:
                    try:
                        self.element = Protocol(attrs['value'], bool(inversions & InversionFlag.PROTOCOL))
                    except KeyError as exc:
                        raise FirewallError(errors.INVALID_RULE, "invalid 'protocol' element") from exc
                    in_elements.pop() # protocol
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'tcp-mss-clamp':
                if attr_name == 'value':
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_Tcp_Mss_Clamp(attrs.get('value'))
                    in_elements.pop()
                    attrs.clear()
                    index = index -1
            elif in_element == 'service':
                if attr_name == 'name':
                    attrs[attr_name] = attr_value
                elif attr_name == 'invert':
                    if functions.parse_boolean(attr_value):
                        inversions|= InversionFlag.SERVICE
                    else:
                        inversions &= ~InversionFlag.SERVICE
                elif element in ['not', 'NOT']:
                    if tokens[index + 1].get('attr_name') == 'name':
                        inversions |= InversionFlag.SERVICE
                    elif tokens[index + 1].get('element') in ['destination', 'port', 'protocol', 'source', 'source-port']:
                        inversions |= InversionFlag.get(tokens[index + 1]['element'])
                else:
                    try:
                        if inversions & InversionFlag.SERVICE:
                            flags |= AddressFlag.INVERTED
                        self.element = Service(attrs['name'], bool(inversions & InversionFlag.SERVICE))
                    except KeyError as exc:
                        raise FirewallError(errors.INVALID_RULE, "invalid 'service' element") from exc
                    in_elements.pop() # service
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'port':
                if attr_name in ['port', 'protocol']:
                    attrs[attr_name] = attr_value
                elif attr_name == 'invert':
                    if functions.parse_boolean(attr_value):
                        inversions |= InversionFlag.PORT
                    else:
                        inversions &= ~InversionFlag.PORT
                elif element in ['not', 'NOT']:
                    if tokens[index + 1].get('attr_name') == 'port':
                        inversions |= InversionFlag.PORT
                    elif tokens[index + 1].get('element') in ['destination', 'service', 'source', 'source-port']:
                        inversions |= InversionFlag.get(tokens[index + 1]['element'])
                else:
                    try:
                        self.element = Port(attrs['port'], attrs['protocol'], bool(inversions & InversionFlag.PORT))
                    except KeyError as exc:
                        raise FirewallError(errors.INVALID_RULE, "invalid 'port' element.") from exc
                    in_elements.pop() # port
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'icmp-block':
                if attr_name == 'name':
                    attrs['name'] = attr_value
                elif attr_name == 'invert':
                    if functions.parse_boolean(attr_value):
                        inversions |= InversionFlag.ICMP_BLOCK
                    else:
                        inversions &= ~InversionFlag.ICMP_BLOCK
                elif element in ['not', 'NOT']:
                    if tokens[index + 1].get('attr_name') == 'name':
                        inversions |= InversionFlag.ICMP_BLOCK
                    elif tokens[index + 1].get('element') in ['destination', 'service', 'source']:
                        inversions |= InversionFlag.get(tokens[index + 1]['element'])
                else:
                    try:
                        self.element = IcmpBlock(attrs['name'], bool(inversions & InversionFlag.ICMP_BLOCK))
                    except KeyError as exc:
                        raise FirewallError(errors.INVALID_RULE, "invalid 'icmp-block' element") from exc
                    in_elements.pop() # icmp-block
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'icmp-type':
                if attr_name == 'name':
                    self.element = Rich_IcmpType(attr_value)
                    in_elements.pop() # icmp-type
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'icmp-type' element")
            elif in_element == 'masquerade':
                self.element = Masquerade()
                in_elements.pop()
                attrs.clear()
                index = index -1 # return token to input
            elif in_element == 'forward-port':
                if attr_name in ['port', 'protocol', 'to-port', 'to-addr']:
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_ForwardPort(attrs.get('port'), attrs.get('protocol'), attrs.get('to-port'), attrs.get('to-addr'))
                    in_elements.pop() # forward-port
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'source-port':
                if attr_name in ['port', 'protocol']:
                    attrs[attr_name] = attr_value
                elif attr_name == 'invert':
                    if functions.parse_boolean(attr_value):
                        inversions |= InversionFlag.SOURCE_PORT
                    else:
                        inversions &= ~InversionFlag.SOURCE_PORT
                elif element in ['not', 'NOT']:
                    if tokens[index + 1].get('attr_name') == 'port':
                        inversions |= InversionFlag.SOURCE_PORT
                    elif tokens[index + 1].get('element') in ['destination', 'port', 'protocol', 'service', 'source']:
                        inversions |= InversionFlag.get(tokens[index + 1]['element'])
                else:
                    try:
                        self.element = SourcePort(attrs['port'], attrs['protocol'], bool(inversions & InversionFlag.SOURCE_PORT))
                    except KeyError as exc:
                        raise FirewallError(errors.INVALID_RULE, "invalid 'source-port' element.") from exc
                    in_elements.pop() # source-port
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'log':
                if attr_name in ['prefix', 'level']:
                    attrs[attr_name] = attr_value
                elif element == 'limit':
                    in_elements.append('limit')
                else:
                    self.log = Rich_Log(attrs.get('prefix'), attrs.get('level'), attrs.get('limit'))
                    in_elements.pop() # log
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'nflog':
                if attr_name in ['group', 'prefix', 'queue-size']:
                    attrs[attr_name] = attr_value
                elif element == 'limit':
                    in_elements.append('limit')
                else:
                    self.log = Rich_NFLog(attrs.get('group'), attrs.get('prefix'), attrs.get('queue-size'), attrs.get('limit'))
                    in_elements.pop() # nflog
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'audit':
                if element == 'limit':
                    in_elements.append('limit')
                else:
                    self.audit = Rich_Audit(attrs.get('limit'))
                    in_elements.pop() # audit
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'accept':
                if element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Accept(attrs.get('limit'))
                    in_elements.pop() # accept
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'drop':
                if element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Drop(attrs.get('limit'))
                    in_elements.pop() # drop
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'reject':
                if attr_name == 'type':
                    attrs[attr_name] = attr_value
                elif element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Reject(attrs.get('type'), attrs.get('limit'))
                    in_elements.pop() # accept
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'mark':
                if attr_name == 'set':
                    attrs[attr_name] = attr_value
                elif element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Mark(attrs.get('set'),
                                            attrs.get('limit'))
                    in_elements.pop() # accept
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'limit':
                if attr_name == 'value':
                    attrs['limit'] = Rich_Limit(attr_value)
                    in_elements.pop() # limit
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'limit' element")

            index = index + 1

        self.check()

    def check(self):
        if self.family is not None and self.family not in [ "ipv4", "ipv6" ]:
            raise FirewallError(errors.INVALID_FAMILY, self.family)
        if self.family is None:
            if (self.source is not None and self.source.flags & AddressFlag.ADDRESS) or \
               self.destination is not None:
                raise FirewallError(errors.MISSING_FAMILY)
            if type(self.element) == Rich_ForwardPort:
                raise FirewallError(errors.MISSING_FAMILY)

        if self.priority < self.priority_min or self.priority > self.priority_max:
            raise FirewallError(errors.INVALID_PRIORITY, "'priority' attribute must be between %d and %d." \
                                                         % (self.priority_min, self.priority_max))

        if self.element is None and \
           (self.log is None or (self.log is not None and self.priority == 0)):
            if self.action is None:
                raise FirewallError(errors.INVALID_RULE, "no element, no action")
            if self.source is None and self.destination is None and self.priority == 0:
                raise FirewallError(errors.INVALID_RULE, "no element, no source, no destination")

        if type(self.element) not in [ IcmpBlock,
                                       Rich_ForwardPort,
                                       Masquerade,
                                       Rich_Tcp_Mss_Clamp ]:
            if self.log is None and self.audit is None and \
                    self.action is None:
                raise FirewallError(errors.INVALID_RULE, "no action, no log, no audit")

        # source
        if self.source is not None:
            if self.source.flags & AddressFlag.ADDRESS:
                if self.family is None:
                    raise FirewallError(errors.INVALID_FAMILY)
                if self.source.flags & AddressFlag.MAC:
                    raise FirewallError(errors.INVALID_RULE, "address and mac")
                if self.source.flags & AddressFlag.IPSET:
                    raise FirewallError(errors.INVALID_RULE, "address and ipset")
                if not functions.check_address(self.family, self.source.address):
                    raise FirewallError(errors.INVALID_ADDR, str(self.source.address))

            elif self.source.flags & AddressFlag.MAC:
                if self.source.flags & AddressFlag.IPSET:
                    raise FirewallError(errors.INVALID_RULE, "mac and ipset")
                if not functions.check_mac(self.source.address):
                    raise FirewallError(errors.INVALID_MAC, str(self.source.address))

            elif self.source.flags & AddressFlag.IPSET:
                if not check_ipset_name(self.source.address):
                    raise FirewallError(errors.INVALID_IPSET, str(self.source.address))

            else:
                raise FirewallError(errors.INVALID_RULE, "invalid source")

        # destination
        if self.destination is not None:
            if self.destination.flags & AddressFlag.ADDRESS:
                if self.family is None:
                    raise FirewallError(errors.INVALID_FAMILY)
                if self.destination.flags & AddressFlag.IPSET:
                    raise FirewallError(errors.INVALID_DESTINATION, "address and ipset")
                if not functions.check_address(self.family, self.destination.address):
                    raise FirewallError(errors.INVALID_ADDR, str(self.destination.addr))

            elif self.destination.flags & AddressFlag.IPSET:
                if not check_ipset_name(self.destination.address):
                    raise FirewallError(errors.INVALID_IPSET, str(self.destination.address))

            else:
                raise FirewallError(errors.INVALID_RULE, "invalid destination")

        # service
        if type(self.element) == Service:
            # service availability needs to be checked in Firewall, here is no
            # knowledge about this, therefore only simple check
            if self.element.name is None or len(self.element.name) < 1:
                raise FirewallError(errors.INVALID_SERVICE, str(self.element.name))

        # port
        elif type(self.element) == Port:
            if not functions.check_port(self.element.port):
                raise FirewallError(errors.INVALID_PORT, self.element.port)
            if self.element.protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.protocol)

        # protocol
        elif type(self.element) == Protocol:
            if not functions.checkProtocol(self.element.value):
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.value)

        # masquerade
        elif type(self.element) == Masquerade:
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "masquerade and action")
            if self.source is not None and self.source.flags & AddressFlag.MAC:
                raise FirewallError(errors.INVALID_RULE, "masquerade and mac source")

        # icmp-block
        elif type(self.element) == IcmpBlock:
            # icmp type availability needs to be checked in Firewall, here is no
            # knowledge about this, therefore only simple check
            if self.element.name is None or len(self.element.name) < 1:
                raise FirewallError(errors.INVALID_ICMPTYPE, str(self.element.name))
            if self.action:
                raise FirewallError(errors.INVALID_RULE, "icmp-block and action")

        # icmp-type
        elif type(self.element) == Rich_IcmpType:
            # icmp type availability needs to be checked in Firewall, here is no
            # knowledge about this, therefore only simple check
            if self.element.name is None or len(self.element.name) < 1:
                raise FirewallError(errors.INVALID_ICMPTYPE, str(self.element.name))

        # forward-port
        elif type(self.element) == Rich_ForwardPort:
            if not functions.check_port(self.element.port):
                raise FirewallError(errors.INVALID_PORT, self.element.port)
            if self.element.protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.protocol)
            if self.element.to_port == "" and self.element.to_address == "":
                raise FirewallError(errors.INVALID_PORT, self.element.to_port)
            if self.element.to_port != "" and \
                    not functions.check_port(self.element.to_port):
                raise FirewallError(errors.INVALID_PORT, self.element.to_port)
            if self.element.to_address != "" and \
                    not functions.check_single_address(self.family,
                                                       self.element.to_address):
                raise FirewallError(errors.INVALID_ADDR, self.element.to_address)
            if self.family is None:
                raise FirewallError(errors.INVALID_FAMILY)
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "forward-port and action")

        # source-port
        elif type(self.element) == SourcePort:
            if not functions.check_port(self.element.port):
                raise FirewallError(errors.INVALID_PORT, self.element.port)
            if self.element.protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.protocol)

        # tcp-mss-clamp
        elif type(self.element) == Rich_Tcp_Mss_Clamp:
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "tcp-mss-clamp and %s are mutually exclusive" % self.action)
            if self.element.value:
                if not functions.checkTcpMssClamp(self.element.value):
                    raise FirewallError(errors.INVALID_RULE, self.element.value)

        # other element and not empty?
        elif self.element is not None:
            raise FirewallError(errors.INVALID_RULE, "Unknown element %s" %
                                type(self.element))

        # log
        if self.log is not None:
            self.log.check()

        # audit
        if self.audit is not None:
            if type(self.action) not in [ Rich_Accept, Rich_Reject, Rich_Drop ]:
                raise FirewallError(errors.INVALID_AUDIT_TYPE, type(self.action))

            if self.audit.limit is not None:
                self.audit.limit.check()

        # action
        if self.action is not None:
            if type(self.action) == Rich_Reject:
                self.action.check(self.family)
            elif type(self.action) == Rich_Mark:
                self.action.check()

            if self.action.limit is not None:
                self.action.limit.check()

    def __str__(self):
        ret = 'rule'
        if self.priority:
            ret += ' priority="%d"' % self.priority
        if self.family:
            ret += ' family="%s"' % self.family
        if self.source:
            ret += " %s" % self.source
        if self.destination:
            ret += " %s" % self.destination
        if self.element:
            ret += " %s" % self.element
        if self.log:
            ret += " %s" % self.log
        if self.audit:
            ret += " %s" % self.audit
        if self.action:
            ret += " %s" % self.action

        return ret


#class Rich_RawRule(object):
#class Rich_RuleSet(object):
#class Rich_AddressList(object):
