"""
Builds a STIX TTP from a CAPEC number.

This script will take a CAPEC ID and transform it into a
STIX TTP object. Work in progress.
"""

import json
import sys

from lxml import objectify

with open('config.json') as data_file:
    CONFIG = json.load(data_file)


def _get_description(attack):
    if not hasattr(attack, "Description"):
        return ""

    node = attack.Description.Summary
    while len(node.getchildren()) > 0:
        node = node.getchildren()[0]

    return node.text


def _get_attack(root, attackid):
    ret = {}
    for attack in root.Attack_Patterns.getchildren():
        if int(attack.get("ID")) == int(attackid):
            record = {
                "id": int(attack.get("ID")),
                "name": attack.get("Name"),
                "description": _get_description(attack),
                "related_attacks": [],
                "attack_prerequisites": [],
            }
            if hasattr(attack, "Related_Attack_Patterns"):
                for r_attack in attack.Related_Attack_Patterns.getchildren():
                    record["related_attacks"].append(
                        (int(r_attack.Relationship_Target_ID.text), r_attack.Relationship_Nature.text))

            if hasattr(attack, "Attack_Prerequisites"):
                for a_requ in attack.Attack_Prerequisites.getchildren():
                    record["attack_prerequisites"].append(str(a_requ.Text))
            ret = record

    return ret


def _main(capecid):
    with open(CONFIG['capec-file'], "r") as capec_file:
        root = objectify.fromstring(capec_file.read())
    print json.dumps(_get_attack(root, capecid), indent=2)

if __name__ == '__main__':
    _main(sys.argv[1])
