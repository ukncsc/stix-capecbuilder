"""
Builds a STIX TTP from a CAPEC number.

This script will take a CAPEC ID and transform it into a
STIX TTP object. Work in progress.
"""

import json
import sys

from lxml import objectify
from stix.common import Identity, InformationSource
from stix.core import STIXHeader, STIXPackage
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.ttp import TTP, Behavior
from stix.ttp.behavior import AttackPattern

import common.ingest as ingest
import common.taxii as taxii

with open('config.json') as data_file:
    CONFIG = json.load(data_file)

NS_PREFIX = CONFIG['stix'][0]['ns_prefix']
NS = CONFIG['stix'][0]['ns']
HNDL_ST = "This information may be distributed without restriction."


def _marking():
    """Define the TLP marking and the inheritance."""
    marking_specification = MarkingSpecification()
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    marking_specification.controlled_structure = "../../../../descendant"\
        "-or-self::node() | ../../../../descendant-or-self::node()/@*"
    simple = SimpleMarkingStructure()
    simple.statement = HNDL_ST
    marking_specification.marking_structures.append(simple)
    handling = Marking()
    handling.add_marking(marking_specification)
    return handling


def _get_description(attack):
    if not hasattr(attack, "Description"):
        return ""

    node = attack.Description.Summary
    while len(node.getchildren()) > 0:
        node = node.getchildren()[0]

    return node.text


def _get_attack(attackid):
    with open(CONFIG['capec-file'], "r") as capec_file:
        root = objectify.fromstring(capec_file.read())
        ret = {}
        for attack in root.Attack_Patterns.getchildren():
            if int(attack.get("ID")) == int(attackid):
                record = {
                    "id": int(attack.get("ID")),
                    "name": attack.get("Name"),
                    "description": _get_description(attack),
                    "related_attacks": [],
                    "attack_prerequisites": [],
                    "references": [],
                }
                if hasattr(attack, "Related_Attack_Patterns"):
                    for r_attack in attack.Related_Attack_Patterns.getchildren():
                        record["related_attacks"].append(
                            (int(r_attack.Relationship_Target_ID.text)))

                if hasattr(attack, "References"):
                    for ref in attack.References.getchildren():
                        if hasattr(ref, "Reference_Link"):
                            record["references"].append(
                                ref.Reference_Link.text)

                if hasattr(attack, "Attack_Prerequisites"):
                    for a_requ in attack.Attack_Prerequisites.getchildren():
                        record["attack_prerequisites"].append(str(a_requ.Text))
                ret = record

    return ret


def _postconstruct(xml, title):
    if CONFIG['ingest'][0]['active'] == True:
        try:
            ingest.inbox_package(CONFIG['ingest'][0]['endpoint'] +
                                 CONFIG['ingest'][0]['user'], xml)
            print("[+] Successfully ingested " + title)
        except ValueError:
            print("[+] Failed ingestion for " + title)
    elif CONFIG['taxii'][0]['active'] == True:
        try:
            taxii.taxii(xml, CONFIG['taxii'][0]['host'],
                        CONFIG['taxii'][0]['ssl'], CONFIG[
                'taxii'][0]['discovery_path'],
                CONFIG['taxii'][0]['binding'], CONFIG[
                'taxii'][0]['username'],
                CONFIG['taxii'][0]['password'],
                CONFIG['taxii'][0]['inbox_path'])
            print("[+] Successfully inboxed " + title)
        except requests.exceptions.ConnectionError:
            print("[+] Failed inbox for " + title)
    else:
        with open(title + ".xml", "w") as text_file:
            text_file.write(xml)
        print("[+] Successfully generated " + title)


def _buildttp(data):
    ttp = TTP()
    ttp.title = data['name']
    ttp.description = data['description']
    attack_pattern = AttackPattern()
    attack_pattern.capec_id = "CAPEC-" + str(data['id'])
    attack_pattern.title = data['name']
    attack_pattern.description = data['description']
    ttp.behavior = Behavior()
    ttp.behavior.add_attack_pattern(attack_pattern)
    ttp.information_source = InformationSource()
    ttp.information_source.identity = Identity()
    ttp.information_source.identity.name = "The MITRE Corporation"
    ttp.information_source.references = data['references']
    return ttp


def capecbuild(capecid):
    """Build a STIX package based on a CAPEC ID."""
    data = _get_attack(capecid)
    if data:
        try:
            from stix.utils import set_id_namespace
            namespace = {NS: NS_PREFIX}
            set_id_namespace(namespace)
        except ImportError:
            from stix.utils import idgen
            from mixbox.namespaces import Namespace
            namespace = Namespace(NS, NS_PREFIX, "")
            idgen.set_id_namespace(namespace)

        pkg = STIXPackage()
        pkg.stix_header = STIXHeader()
        pkg = STIXPackage()
        pkg.stix_header = STIXHeader()
        pkg.stix_header.handling = _marking()

        ttp = _buildttp(data)

        if data['related_attacks']:
            ttp.related_ttps.append(
                _buildttp(_get_attack(str(data['related_attacks'][0]))))
        pkg.add_ttp(ttp)
        xml = pkg.to_xml()
        title = pkg.id_.split(':', 1)[-1]
        if __name__ == '__main__':
            _postconstruct(xml, title)
    return xml


if __name__ == '__main__':
    capecbuild(sys.argv[1])
