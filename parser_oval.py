import json
import xml.etree.ElementTree as ET
import re
import sys

namespace = {
    "common": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "oval": "http://oval.mitre.org/XMLSchema/oval-common-5",
    "unix-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
    "red-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
    "ind-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
}

patches = list()

number_patches: int = 3
current_patches = []
platform_inf: dict = {}
description: str = ""
cve: dict = {}
modified_metadata: dict = {}
criteria_criterion_dict: dict = {}
generator: dict = {'Information_about_file': {}, 'Patches': {}}


def generator_oval(root: ET.Element):
    global generator
    for child in root.findall('./common:generator', namespaces=namespace):
        product_name = child.find("oval:product_name", namespaces=namespace).text
        product_version = child.find("oval:product_version", namespaces=namespace).text
        oval_scheme = child.find("oval:schema_version", namespaces=namespace).text
        timestamp = child.find("oval:timestamp", namespaces=namespace).text
        content_version = child.find("oval:content_version", namespaces=namespace).text
        temp_dict = {
            'product_name': product_name, "product_version": product_version,
            "oval_scheme": oval_scheme, "timestamp": timestamp,
            "content_version": content_version
        }
        generator.get('Information_about_file').update(temp_dict)


def definitions(root: ET.Element):
    global platform_inf
    global description
    global cve
    global modified_metadata
    current_tests = set()
    for one_test in root.findall("./common:tests/",
                                 namespaces=namespace):
        current_tests.add(one_test.tag)

    for child in root.findall('./common:definitions', namespaces=namespace):
        patches = child.findall('*', namespaces=namespace)

        for i in range(number_patches):

            generator.get('Patches').update({'Patch #' + str(i): {'Information': {}, 'Checks': {}}})
            modified_metadata.update({"definition": {}, "metadata": {}})
            modified_metadata.update({"definition": patches[i].attrib})
            current_patches.append(patches[i])
            metadata = current_patches[i].find('./common:metadata', namespaces=namespace)
            criteria = current_patches[i].find('./common:criteria',
                                               namespaces=namespace)

            start_operators = 0  # count of operators (OR,AND)

            for ch in criteria.iter('{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria'):  # get checks
                first_ch = ch
                next_criteria: list = ch.findall('./common:criteria', namespaces=namespace)
                modif_next_criteria = list()
                count_operators = start_operators + 1
                for crit in next_criteria:
                    modif_next_criteria.append(crit.attrib.get('operator') + str(count_operators))
                    count_operators += 1

                current_criterion: list = ch.findall('./common:criterion', namespaces=namespace)

                objects_and_states_of_test = dict()
                count_test = 0
                for criton in current_criterion:
                    test_ref = criton.attrib.get('test_ref')
                    for type_of_test in current_tests:
                        for one_test in root.findall("./common:tests/" + type_of_test + "[@id=\'" + test_ref + "\']",
                                                     namespaces=namespace):
                            objects_and_states_of_test.update({'test_items' + str(count_test): one_test.attrib})

                            type_of_obj: str = str(type_of_test)
                            type_of_obj = type_of_obj.replace("_test", "_object")

                            type_of_state: str = str(type_of_test)
                            type_of_state = type_of_state.replace("_test", "_state")

                            for one_object in root.findall(
                                    "./common:objects/" + type_of_obj + "[@id=\'" + one_test[0].attrib.get(
                                        'object_ref') + "\']",
                                    namespaces=namespace):
                                if len(one_object[0].attrib) == 0:
                                    # print(one_object[0].text)
                                    objects_and_states_of_test.update(
                                        {'object_items' + str(count_test): one_object[0].text})
                                if one_object[0].text is None:
                                    objects_and_states_of_test.update(
                                        {'object_items' + str(count_test): one_object[0].attrib})
                                if len(one_object[0].attrib) != 0 and one_object[0].text is not None:
                                    # print(one_object[0].attrib, one_object[0].text)
                                    temp_dict: dict = one_object[0].attrib
                                    temp_dict.update({'value': one_object[0].text})
                                    objects_and_states_of_test.update({'object_items' + str(count_test): temp_dict})
                            for one_state in root.findall(
                                    "./common:states/" + type_of_state + "[@id=\'" + one_test[1].attrib.get(
                                        'state_ref') + "\']",
                                    namespaces=namespace):
                                if len(one_state[0].attrib) == 0:
                                    objects_and_states_of_test.update(
                                        {'state_items' + str(count_test): one_state[0].text})
                                if one_state[0].text is None:
                                    objects_and_states_of_test.update(
                                        {'state_items' + str(count_test): one_state[0].attrib})
                                if len(one_state[0].attrib) != 0 and one_state[0].text is not None:
                                    temp_dict: dict = one_state[0].attrib
                                    temp_dict.update({'value': one_state[0].text})
                                    objects_and_states_of_test.update({'state_items' + str(count_test): temp_dict})
                            count_test += 1

                    criteria_criterion_dict.update({first_ch.attrib.get('operator') +
                                                    str(start_operators): {'criterion': objects_and_states_of_test,
                                                                           'next': modif_next_criteria}})
                start_operators += 1

            patch_information = metadata.findall('*', namespaces=namespace)  # get information about patch
            for data in patch_information:
                if len(re.findall("title", data.tag)) == 1:
                    # print(data.text)
                    modified_metadata.get("metadata").update({"title": data.text})
                if len(re.findall("affected", data.tag)) == 1:
                    platform_inf = data.attrib
                    platform = data.find('./common:platform', namespaces=namespace).text
                    platform_inf.update({"platform": platform})
                    modified_metadata.get("metadata").update({"platform_and_cpe": platform_inf})

                if len(re.findall("description", data.tag)) == 1:
                    description = data.text
                    description = description.replace("\n", "")
                    modified_metadata.get("metadata").update({"description": description})

                severity = data.find('./common:severity', namespaces=namespace)
                if severity is not None:
                    modified_metadata.get("metadata").update({"severity": severity.text})

                if len(re.findall("advisory", data.tag)) == 1:
                    affected_cpe_list: list = data.findall('./common:affected_cpe_list/common:cpe',
                                                           namespaces=namespace)
                    cpe_list = list()
                    for cpe in affected_cpe_list:
                        cpe_list.append(cpe.text)
                    platform_inf.update({'affected_cpe_list': cpe_list})
                    modified_metadata.get("metadata").update({"platform_and_cpe": platform_inf})
                    cve_list: list = data.findall('./common:cve', namespaces=namespace)
                    modified_cve_dict = dict()
                    cout_cve: int = 1
                    for cve in cve_list:
                        modified_cve_dict.update({"cve" + str(cout_cve): cve.attrib})
                        cout_cve += 1
                    modified_metadata.get("metadata").update({"cve": modified_cve_dict})
                    # print(json.dumps(modified_metadata, indent=3))

            generator.get('Patches').get('Patch #' + str(i)).get('Information').update(modified_metadata)
            generator.get('Patches').get('Patch #' + str(i)).get('Checks').update(criteria_criterion_dict)

            with open('result.json', 'w') as f:
                json.dump(generator, f, indent=3)

            modified_metadata = {"patch": {"definition": {}, "metadata": {}}}
            criteria_criterion_dict.clear()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Choose xml file')
    else:
        xml_file = ET.parse(sys.argv[1])
        root = xml_file.getroot()
        generator_oval(root)
        definitions(root)
