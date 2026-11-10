from unittest import TestCase
from tempfile import TemporaryDirectory

from logsource_mapping import *


class TestServiceFieldMappings(TestCase):
    def convert(self, detection, service="windefend", fields=None, logsource=None):
        channels = {
            "windefend": "Microsoft-Windows-Windows Defender/Operational",
            "security": "Security", "system": "System",
            "wmi": "Microsoft-Windows-WMI-Activity/Operational",
            "smbclient-connectivity": "Microsoft-Windows-SmbClient/Connectivity",
            "terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        }
        obj = {"title": "Scoped service fields", "id": "e5b97fea-a1d2-4b88-bf29-cc98d3e7ef00",
               "logsource": {"product": "windows", "service": service}, "detection": detection}
        if fields is not None:
            obj["fields"] = fields
        ls = logsource or LogSource(None, service, channels[service], None)
        return LogsourceConverter("test.yml", {}, {}).convert_rule(obj, ls)

    def test_defender_5007_values_keep_modifiers(self):
        result = self.convert({"selection": {"EventID": 5007, "NewValue|contains|all": ["one", "two"],
                                             "OldValue|endswith": "three"}, "condition": "selection"})
        self.assertEqual(result["detection"]["selection"],
                         {"EventID": 5007, "New_Value|contains|all": ["one", "two"], "Old_Value|endswith": "three"})

    def test_separate_predicates_inherit_a_proven_5007_scope(self):
        detection = {"allowed_apps_key": {"EventID": 5007, "NewValue|contains": "AllowedApplications"},
                     "allowed_apps_path": {"NewValue|contains": ["\\Users\\Public\\", "\\Windows\\Temp\\"]},
                     "protected_folders": {"EventID": 5007, "OldValue|contains": "ProtectedFolders"},
                     "condition": "all of allowed_apps* or protected_folders"}
        converted = self.convert(detection)["detection"]
        self.assertIn("New_Value|contains", converted["allowed_apps_path"])
        self.assertIn("Old_Value|contains", converted["protected_folders"])

    def test_other_events_and_unproven_scopes_keep_original_value_fields(self):
        for event_id in [5001, 1116, [5007, 5001], "500*", None]:
            with self.subTest(event_id=event_id):
                selection = {"NewValue": "new", "OldValue": "old"}
                if event_id is not None:
                    selection["EventID"] = event_id
                result = self.convert({"selection": selection, "condition": "selection"})
                self.assertEqual(result["detection"]["selection"], selection)

    def test_mixed_event_branches_only_rename_the_5007_branch(self):
        result = self.convert({"config": {"EventID": 5007, "NewValue": "new"},
                               "other": {"EventID": 5001, "NewValue": "other"},
                               "condition": "config or other"})["detection"]
        self.assertIn("New_Value", result["config"])
        self.assertIn("NewValue", result["other"])

    def test_selector_alternatives_keep_their_own_event_scopes(self):
        result = self.convert({"selection": [{"EventID": 5007, "NewValue": "a"},
                                               {"EventID": 5001, "NewValue": "b"}],
                               "condition": "selection"})["detection"]["selection"]
        self.assertEqual(result, [{"EventID": 5007, "New_Value": "a"}, {"EventID": 5001, "NewValue": "b"}])

    def test_negated_event_constraint_does_not_enable_a_rule_wide_rename(self):
        for condition in ["not event and path", "not (event) and path", "path or event"]:
            with self.subTest(condition=condition):
                converted = self.convert({"event": {"EventID": 5007}, "path": {"NewValue": "test"},
                                          "condition": condition})["detection"]
                self.assertIn("NewValue", converted["path"])

    def test_and_or_precedence_and_parentheses(self):
        for condition, maps in [("event and path or other", False),
                                ("event and (path or other)", True),
                                ("(event and path) or (event and other)", True)]:
            with self.subTest(condition=condition):
                result = self.convert({"event": {"EventID": 5007}, "path": {"NewValue": "x"},
                                       "other": {"OldValue": "y"}, "condition": condition})["detection"]
                self.assertIn("New_Value" if maps else "NewValue", result["path"])

    def test_all_and_one_of_them(self):
        for condition, maps in [("all of them", True), ("1 of them", False), ("2 of them", False)]:
            with self.subTest(condition=condition):
                result = self.convert({"event": {"EventID": 5007}, "path": {"NewValue": "x"},
                                       "condition": condition})["detection"]
                self.assertIn("New_Value" if maps else "NewValue", result["path"])

    def test_source_and_process_names_apply_to_defender_including_exclusions(self):
        detection = {"selection": {"EventID": 1121, "SourceName": "AMSI"},
                     "filter": {"ProcessName|startswith": "C:\\Windows\\", "ProcessName|endswith": "svchost.exe"},
                     "condition": "selection and not filter"}
        result = self.convert(detection)["detection"]
        self.assertIn("Source_Name", result["selection"])
        self.assertIn("WindowsDefenderProcessName|startswith", result["filter"])
        self.assertIn("WindowsDefenderProcessName|endswith", result["filter"])

    def test_security_fields_are_not_globally_remapped(self):
        selection = {"EventID": 4657, "NewValue": "new", "OldValue": "old", "ProcessName": "reg.exe", "ProcessId": 0}
        result = self.convert({"selection": selection, "condition": "selection"}, service="security")
        self.assertEqual(result["detection"]["selection"], selection)

    def test_smb_address_and_unrelated_source_name_stay_literal(self):
        selection = {"EventID": 30804, "Address|startswith": "192.168.", "SourceName": "test", "ProcessName": "test.exe"}
        result = self.convert({"selection": selection, "condition": "selection"}, service="smbclient-connectivity")
        self.assertEqual(result["detection"]["selection"], selection)

    def test_nested_wmi_and_rdp_fields_are_left_for_hayabusa_lookup(self):
        for service, selection in [
            ("wmi", {"EventID": 5858, "Operation|contains|all": ["Win32_NTEventlogFile", "ClearEventLog"]}),
            ("wmi", {"EventID": 5859, "Provider": "SCM Event Provider", "Query": "select *", "User": "S-1-5-18", "PossibleCause": "Permanent"}),
            ("terminalservices-localsessionmanager", {"EventID": 21, "Address|contains": "16777216"}),
        ]:
            with self.subTest(service=service, selection=selection):
                result = self.convert({"selection": selection, "condition": "selection"}, service=service)
                self.assertEqual(result["detection"]["selection"], selection)

    def test_system_pid_requires_both_7045_and_scm(self):
        for event_id, provider, renamed in [(7045, "Service Control Manager", True),
                                            (7040, "Service Control Manager", False),
                                            (7045, "Another Provider", False), (7045, None, False)]:
            with self.subTest(event_id=event_id, provider=provider):
                selection = {"EventID": event_id, "ProcessId": 0}
                if provider:
                    selection["Provider_Name"] = provider
                result = self.convert({"selection": selection, "condition": "selection"}, service="system")
                self.assertIn("ExecutionProcessID" if renamed else "ProcessId", result["detection"]["selection"])

    def test_system_pid_inherits_separate_scm_and_event_constraints(self):
        result = self.convert({"event": {"EventID": 7045}, "provider": {"ProviderName": "Service Control Manager"},
                               "selection": {"ProcessId": 0}, "condition": "event and provider and selection"}, service="system")
        self.assertEqual(result["detection"]["selection"], {"ExecutionProcessID": 0})

    def test_mixed_channel_logsource_is_not_globally_remapped(self):
        ls = LogSource(None, "mixed", ["Security", "Microsoft-Windows-Windows Defender/Operational"], None)
        selection = {"EventID": 5007, "ProcessName": "x", "NewValue": "y"}
        result = self.convert({"selection": selection, "condition": "selection"}, logsource=ls)
        self.assertEqual(result["detection"]["selection"], selection)

    def test_fields_and_field_references_are_renamed_but_literals_and_selectors_are_not(self):
        result = self.convert({"NewValue": {"EventID": 5007, "NewValue|fieldref": "OldValue",
                                            "SourceName|equalsfield": "ProcessName", "CommandLine|contains": "NewValue"},
                               "condition": "NewValue"}, fields=["NewValue", "OldValue", "ProcessName", "CommandLine"])
        self.assertEqual(result["fields"], ["New_Value", "Old_Value", "WindowsDefenderProcessName", "CommandLine"])
        self.assertIn("NewValue", result["detection"])
        self.assertEqual(result["detection"]["NewValue"]["New_Value|fieldref"], "Old_Value")
        self.assertEqual(result["detection"]["NewValue"]["Source_Name|equalsfield"], "WindowsDefenderProcessName")
        self.assertEqual(result["detection"]["NewValue"]["CommandLine|contains"], "NewValue")
        self.assertEqual(result["detection"]["condition"], "windefend and NewValue")

    def test_legacy_aggregation_fields_are_renamed(self):
        result = self.convert({"selection": {"EventID": 5007, "NewValue|contains": "test"},
                               "condition": "selection | count(NewValue) by OldValue > 1"})
        self.assertIn("count(New_Value) by Old_Value", result["detection"]["condition"])

    def test_mixed_event_output_fields_retain_both_names(self):
        result = self.convert({"config": {"EventID": 5007, "NewValue": "new"},
                               "other": {"EventID": 5001, "NewValue": "other"},
                               "condition": "config or other"}, fields=["NewValue", "CommandLine"])
        self.assertEqual(result["fields"], ["NewValue", "New_Value", "CommandLine"])

    def test_unrelated_output_field_order_and_duplicates_are_preserved(self):
        fields = ["ServiceName", "EventID", "ServiceName"]
        result = self.convert({"selection": {"EventID": 7000}, "condition": "selection"}, service="system", fields=fields)
        self.assertEqual(result["fields"], fields)

    def test_mixed_event_aggregation_cannot_silently_count_the_wrong_field(self):
        with self.assertRaisesRegex(ValueError, "Mixed-event aggregation"):
            self.convert({"config": {"EventID": 5007, "NewValue": "new"},
                          "other": {"EventID": 5001, "NewValue": "other"},
                          "condition": "config or other | count(NewValue) > 1"})

    def test_mapping_collision_is_an_explicit_error(self):
        with self.assertRaisesRegex(ValueError, "mapping collision"):
            self.convert({"selection": {"EventID": 5007, "NewValue": "one", "New_Value": "two"}, "condition": "selection"})

    def test_key_comments_survive_conversion(self):
        rule = ruamel.yaml.YAML().load("""\
title: Comments
id: e5b97fea-a1d2-4b88-bf29-cc98d3e7ef00
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 5007
        NewValue: test # important inline comment
    condition: selection
""")
        ls = LogSource(None, "windefend", "Microsoft-Windows-Windows Defender/Operational", None)
        result = LogsourceConverter("test.yml", {}, {}).convert_rule(rule, ls)
        output = StringIO()
        ruamel.yaml.YAML().dump(result, output)
        self.assertRegex(output.getvalue(), r"New_Value: test\s+# important inline comment")


class TestLogSourceMapper(TestCase):
    def test_create_service_map(self):
        res = create_service_map(create_obj(os.path.dirname(os.path.abspath(__file__)), "services-mapping.yaml")[0])
        self.assertEqual(len(res.keys()), 43)

    def test_create_category_map(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        service_to_channels = create_service_map(create_obj(script_dir, "services-mapping.yaml")[0])
        s1 = create_category_map(create_obj(script_dir, 'sysmon-category-mapping.yaml')[0], service_to_channels)
        s2 = create_category_map(create_obj(script_dir, 'builtin-category-mapping.yaml')[0], service_to_channels)
        s3 = create_category_map(create_obj(script_dir, 'services-mapping.yaml')[0], service_to_channels)
        s4 = merge_category_map(service_to_channels, [s1, s2, s3])
        self.assertEqual(len(s4), 77)
        self.assertEqual(len(s4["process_creation"]), 2)

    def test_build_out_path(self):
        sigma_path = "/hoge/sigma/builtin/security/sample.yml"
        base_dir = "/hoge/sigma"
        out_dir = "/hoge/hayabusa_rule"
        sysmon = True
        r = build_out_path(base_dir, out_dir, sigma_path, sysmon)
        self.assertEqual(r, "/hoge/hayabusa_rule/sysmon/security/sample.yml")
        sysmon = False
        r = build_out_path(base_dir, out_dir, sigma_path, sysmon)
        self.assertEqual(r, "/hoge/hayabusa_rule/builtin/security/sample.yml")

    def test_get_key(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=1)
        self.assertEqual(ls.get_identifier_for_detection([]), "process_creation")

    def test_get_uniq_key(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=1)
        self.assertEqual(ls.get_identifier_for_detection(["process_creation"]), "logsource_mapping_process_creation")

    def test_get_detection(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEqual(ls.get_detection(), {"Channel": "hoge"})

    def test_get_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEqual(ls.get_condition("select1 and select2", [], dict()),
                         "process_creation and (select1 and select2)")

    def test_get_single_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        self.assertEqual(ls.get_condition("select", [], dict()), "process_creation and select")

    def test_get_aggregation_condition(self):
        ls = LogSource(category="process_creation", service="sysmon", channel="hoge", event_id=None)
        condition = "select | count(TargetUserName) by Workstation > 10"
        self.assertEqual(ls.get_condition(condition, [], dict()),
                         "(process_creation and select) | count(TargetUserName) by Workstation > 10")

    def test_get_aggregation_conversion_field_condition(self):
        ls = LogSource(category="process_creation", service="Security", channel="hoge", event_id=4688)
        condition = "select | count(Image) by Workstation > 10"
        self.assertEqual(ls.get_condition(condition, [], {"Image": "NewProcessName"}),
                         "(process_creation and select) | count(NewProcessName) by Workstation > 10")

    def test_multiline_condition_is_dumped_on_one_line(self):
        rule = """\
title: Multiline condition
logsource:
    category: process_creation
detection:
    selection_wevtutil_img:
        Image: wevtutil.exe
    selection_wevtutil_cli_clear:
        CommandLine: cl
    selection_logman_img:
        Image: logman.exe
    selection_logman_update:
        CommandLine: update
    selection_pwsh_img:
        Image: pwsh.exe
    selection_pwsh_cli:
        CommandLine: Set-EtwTraceProvider
    condition: |
        (selection_wevtutil_img and 1 of selection_wevtutil_cli_*)
        or (all of selection_logman_*)
        or (all of selection_pwsh_*)
"""
        logsource = LogSource(
            category="process_creation",
            service="sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            event_id=1,
        )
        expected_condition = (
            "process_creation and ((selection_wevtutil_img and 1 of "
            "selection_wevtutil_cli_*) or (all of selection_logman_*) or "
            "(all of selection_pwsh_*))"
        )

        with TemporaryDirectory() as temp_dir:
            rule_path = Path(temp_dir, "rule.yml")
            rule_path.write_text(rule, encoding="utf-8")
            converter = LogsourceConverter(
                str(rule_path),
                {"process_creation": [logsource]},
                {"process_creation": {}},
            )

            converter.convert()
            _, output = converter.dump_yml("", temp_dir)[0]
            converted = list(ruamel.yaml.YAML().load_all(output))[0]

        self.assertEqual(converted["detection"]["condition"], expected_condition)
        self.assertNotIn("condition: |", output)

    def test_get_logsources(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        service2channel = create_service_map(create_obj(script_dir, "services-mapping.yaml")[0])
        sysmon_map = create_category_map(create_obj(script_dir, 'sysmon-category-mapping.yaml')[0], service2channel)
        win_audit_map = create_category_map(create_obj(script_dir, 'builtin-category-mapping.yaml')[0], service2channel)
        win_service_map = create_category_map(create_obj(script_dir, 'services-mapping.yaml')[0], service2channel)
        all_category_map = merge_category_map(service2channel, [sysmon_map, win_audit_map, win_service_map])
        process_creation_field_map = create_field_map("fieldmappings_process", create_obj(script_dir, 'builtin-category-mapping.yaml')[0])
        lc = LogsourceConverter("", all_category_map, process_creation_field_map, [])
        r = lc.get_logsources({"logsource": {"service": "sysmon"}})
        self.assertEqual(r[0].service, "sysmon")

    def test_get_logsources_raise_exception_if_not_supported_category(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        service2channel = create_service_map(create_obj(script_dir, "services-mapping.yaml")[0])
        sysmon_map = create_category_map(create_obj(script_dir, 'sysmon-category-mapping.yaml')[0], service2channel)
        win_audit_map = create_category_map(create_obj(script_dir, 'builtin-category-mapping.yaml')[0], service2channel)
        win_service_map = create_category_map(create_obj(script_dir, 'services-mapping.yaml')[0], service2channel)
        all_category_map = merge_category_map(service2channel, [sysmon_map, win_audit_map, win_service_map])
        process_creation_field_map = create_field_map("fieldmappings_process", create_obj(script_dir, 'builtin-category-mapping.yaml')[0])
        lc = LogsourceConverter("", all_category_map, process_creation_field_map, [])
        with self.assertRaises(Exception):
            lc.get_logsources({"logsource": {"service": "file_rename"}})

    def test_logsource_validate_security_4688(self):
        ls = LogSource(category="process_creation", event_id=4688, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"Image": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"ParentImage": "b.exe"}}))
        self.assertTrue(ls.is_detectable({"selection": {"NewProcessName": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"ParentProcessName": "b.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"NewProcessName|contains": "c.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {'ParentProcessName|endswith': '\\winword.exe', 'NewProcessName|contains': '/l'}, 'condition': 'selection'}))

    def test_logsource_validate_security_4657(self):
        ls = LogSource(category="registry_set", event_id=4657, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"Image": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"Details": "foo"}}))
        self.assertTrue(ls.is_detectable({"selection": {"ProcessName": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"SubjectUserName": "foo" }}))
        self.assertTrue(ls.is_detectable({"selection": {"NewValue|contains": "c.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {'OperationType|endswith': '%%1904'}, 'condition': 'selection'}))


    def test_logsource_validate_sysmon_1(self):
        ls = LogSource(category="process_creation", event_id=1, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"NewProcessName": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"ParentProcessName": "b.exe"}}))
        self.assertTrue(ls.is_detectable({"selection": {"Image": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"ParentImage": "b.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"Image|contains": "c.exe" }}))
        self.assertTrue(ls.is_detectable({'selection': {'Image|endswith': '\\winword.exe', 'CommandLine|contains': '/l'}, 'condition': 'selection'}))

    def test_logsource_validate_security_12(self):
        ls = LogSource(category="registry_set", event_id=12, service="", channel="")
        self.assertFalse(ls.is_detectable({"selection": {"ProcessName": "a.exe"}}))
        self.assertFalse(ls.is_detectable({"selection": {"NewValue": "foo"}}))
        self.assertTrue(ls.is_detectable({"selection": {"Image": "a.exe" }}))
        self.assertTrue(ls.is_detectable({"selection": {"Details": "foo" }}))
        self.assertTrue(ls.is_detectable({"selection": {"EventType": "CreateKey" }}))
        self.assertTrue(ls.is_detectable({"selection": {'TargetObject|endswith': 'software'}, 'condition': 'selection'}))

    def test_assign_uuid(self):
        original_uuid = "557e3885-7a7e-40b7-8b69-1e5e658ca1d1"
        inp = {"title": "X", "id": original_uuid, "related": [{"id": "a", "type": "similar"}]}
        res = assign_uuid_for_convert_rules(inp, "abc")
        self.assertEqual(res, {"title":"X", "id": "04428db4-0588-7e14-0c46-c99384f8fc4c", "related": [{'id': 'a', 'type': 'similar'}, {"id": original_uuid, "type": "derived"}]})

    def _registry_event_logsources(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        service2channel = create_service_map(create_obj(script_dir, "services-mapping.yaml")[0])
        sysmon_map = create_category_map(create_obj(script_dir, 'sysmon-category-mapping.yaml')[0], service2channel)
        win_audit_map = create_category_map(create_obj(script_dir, 'builtin-category-mapping.yaml')[0], service2channel)
        all_category_map = merge_category_map(service2channel, [sysmon_map, win_audit_map])
        registry_field_map = create_field_map("fieldmappings_registry", create_obj(script_dir, 'builtin-category-mapping.yaml')[0])
        field_map = {"registry_event": registry_field_map}
        return all_category_map["registry_event"], field_map

    def _azorult_rule(self):
        return {
            "title": "Registry Entries For Azorult Malware",
            "id": "f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7",
            "logsource": {"product": "windows", "category": "registry_event"},
            "detection": {
                "selection": {
                    "EventID": [12, 13],
                    "TargetObject|contains": "SYSTEM\\",
                    "TargetObject|endswith": "\\services\\localNETService",
                },
                "condition": "selection",
            },
        }

    def test_registry_event_drops_incompatible_eventid_for_security(self):
        # A registry_event rule that hardcodes the Sysmon IDs 12/13 must not AND
        # them with the Security-log EventID 4657 (that can never match). The
        # Sysmon-only EventID should be dropped so the Security rule is usable,
        # while the Sysmon conversion keeps the overlapping EventID.
        logsources, field_map = self._registry_event_logsources()
        for ls in logsources:
            lc = LogsourceConverter("azorult.yml", {}, field_map)
            converted = lc.convert_rule(self._azorult_rule(), ls)
            if ls.event_id == 4657:  # Security
                self.assertIsNotNone(converted)
                self.assertNotIn("EventID", converted["detection"]["selection"])
                self.assertEqual(converted["detection"]["registry_event"]["EventID"], 4657)
                self.assertIn("ObjectName|contains", converted["detection"]["selection"])
            else:  # Sysmon (12/13/14) overlaps 12/13, so it is kept
                self.assertIsNotNone(converted)
                self.assertEqual(converted["detection"]["selection"]["EventID"], [12, 13])


class TestCategoryEventIDRestrictions(TestCase):
    @classmethod
    def setUpClass(cls):
        directory = os.path.dirname(os.path.abspath(__file__))
        services = create_service_map(create_obj(directory, "services-mapping.yaml")[0])
        native = create_obj(directory, "builtin-category-mapping.yaml")[0]
        cls.logs = merge_category_map(services, [
            create_category_map(create_obj(directory, "sysmon-category-mapping.yaml")[0], services),
            create_category_map(native, services),
        ])
        cls.fields = {}
        for categories, mapping in [
            (["registry_event", "registry_set", "registry_add", "registry_delete"], "registry"),
            (["process_creation"], "process"), (["network_connection"], "network"),
            (["wmi_event"], "wmi"),
        ]:
            for category in categories:
                cls.fields[category] = create_field_map("fieldmappings_" + mapping, native)

    def convert(self, detection, category="registry_event", service="security"):
        obj = {"title": "Event ID restriction regression", "id": "da57aa42-d688-43d4-a1bc-63f421b7a967",
               "logsource": {"product": "windows", "category": category}, "detection": detection}
        logsource = next(ls for ls in self.logs[category] if ls.service == service)
        return LogsourceConverter("eventid-regression.yml", {}, self.fields).convert_rule(obj, logsource)

    def test_source_id_is_removed_only_when_target_supplies_its_equivalent(self):
        for ids in [13, "13", [13], ["12", "13"], [12, 13, 14]]:
            with self.subTest(ids=ids):
                result = self.convert({"selection": {"EventID": ids, "TargetObject|endswith": "\\malware"},
                                       "condition": "selection"})["detection"]
                self.assertEqual(result["registry_event"]["EventID"], 4657)
                self.assertEqual(result["selection"], {"ObjectName|endswith": "\\malware"})

    def test_sysmon_subsets_are_preserved_including_their_original_types(self):
        for ids in [12, 13, 14, [12, 13], ["12", "13"], [12, 13, 14]]:
            with self.subTest(ids=ids):
                result = self.convert({"selection": {"EventID": ids, "TargetObject|endswith": "\\malware"},
                                       "condition": "selection"}, service="sysmon")["detection"]
                self.assertEqual(result["selection"]["EventID"], ids)

    def test_correct_security_id_is_not_removed(self):
        for ids in [4657, "4657", [4657], [13, 4657]]:
            with self.subTest(ids=ids):
                result = self.convert({"selection": {"EventID": ids, "TargetObject|endswith": "\\malware"},
                                       "condition": "selection"})["detection"]
                self.assertEqual(result["selection"]["EventID"], ids)

    def test_service_specific_event_ids_remain_unchanged(self):
        for service, channel, ids in [("security", "Security", [4657, 4697]),
                                      ("system", "System", 7045),
                                      ("windefend", DEFENDER_CHANNEL, 5007),
                                      ("wmi", "Microsoft-Windows-WMI-Activity/Operational", 5859)]:
            with self.subTest(service=service):
                obj = {"title": "Native IDs", "id": "da57aa42-d688-43d4-a1bc-63f421b7a967",
                       "logsource": {"product": "windows", "service": service},
                       "detection": {"selection": {"EventID": ids}, "condition": "selection"}}
                ls = LogSource(None, service, channel, None)
                result = LogsourceConverter("native.yml", {}, {}).convert_rule(obj, ls)
                self.assertEqual(result["detection"]["selection"]["EventID"], ids)

    def test_negative_filters_keep_unrepresentable_ids(self):
        for ids in [12, 14, 9999, [12, 14]]:
            with self.subTest(ids=ids):
                result = self.convert({"selection": {"TargetObject|contains": "malware"},
                                       "filter": {"EventID": ids, "TargetObject|contains": "benign"},
                                       "condition": "selection and not filter"})["detection"]
                self.assertEqual(result["filter"]["EventID"], ids)
                self.assertEqual(result["filter"]["ObjectName|contains"], "benign")

    def test_representable_negative_filter_keeps_its_remaining_predicates(self):
        result = self.convert({"selection": {"TargetObject|contains": "malware"},
                               "filter": {"EventID": 13, "TargetObject|contains": "benign"},
                               "condition": "selection and not filter"})["detection"]
        self.assertEqual(result["filter"], {"ObjectName|contains": "benign"})

    def test_event_only_selectors_and_filters_do_not_become_empty_maps(self):
        for ids, expected in [(13, 4657), ("13", 4657), ([12, 13], [4657])]:
            with self.subTest(ids=ids):
                result = self.convert({"selection": {"EventID": ids}, "condition": "selection"})
                self.assertEqual(result["detection"]["selection"], {"EventID": expected})
        result = self.convert({"selection": {"TargetObject|contains": "malware"},
                               "filter": {"EventID": 13}, "condition": "selection and not filter"})
        self.assertEqual(result["detection"]["filter"], {"EventID": 4657})

    def test_reverse_registry_conversion_preserves_the_narrower_value_set_scope(self):
        result = self.convert({"selection": {"EventID": 4657, "TargetObject|contains": "malware"},
                               "condition": "selection"}, service="sysmon")["detection"]
        self.assertEqual(result["registry_event"]["EventID"], [12, 13, 14])
        self.assertEqual(result["selection"]["EventID"], 13)

    def test_unsupported_positive_restrictions_skip_instead_of_broadening(self):
        for ids in [12, 14, [12, 14], 9999]:
            with self.subTest(ids=ids):
                self.assertIsNone(self.convert({"selection": {"EventID": ids, "TargetObject|contains": "malware"},
                                                "condition": "selection"}))

    def test_or_branches_do_not_broaden_or_discard_a_valid_alternative(self):
        for detection in [
            {"creation": {"EventID": 12, "TargetObject|contains": "creation"},
             "value": {"EventID": 13, "TargetObject|contains": "value"}, "condition": "creation or value"},
            {"creation": {"EventID": 12, "TargetObject|contains": "creation"},
             "value": {"EventID": 13, "TargetObject|contains": "value"}, "condition": "1 of *"},
        ]:
            with self.subTest(condition=detection["condition"]):
                result = self.convert(detection)["detection"]
                self.assertEqual(result["creation"]["EventID"], 12)
                self.assertEqual(result["value"], {"ObjectName|contains": "value"})
        result = self.convert({"selection": [{"EventID": 12, "TargetObject|contains": "creation"},
                                             {"EventID": 13, "TargetObject|contains": "value"}],
                               "condition": "selection"})["detection"]
        self.assertEqual(result["selection"], [{"EventID": 12, "ObjectName|contains": "creation"},
                                               {"ObjectName|contains": "value"}])

    def test_unknown_ids_in_a_mixed_list_are_not_silently_removed(self):
        result = self.convert({"selection": {"EventID": [13, 9999], "TargetObject|contains": "malware"},
                               "condition": "selection"})["detection"]
        self.assertEqual(result["selection"]["EventID"], [4657, 9999])

    def test_nonliteral_and_modified_eventid_tests_are_preserved(self):
        for key, value in [("EventID", "13*"), ("EventID|re", "^13$"),
                           ("EventID|gte", 12), ("EventID|fieldref", "OtherID")]:
            with self.subTest(key=key):
                result = self.convert({"selection": {key: value, "TargetObject|contains": "malware"},
                                       "condition": "selection"})["detection"]
                self.assertEqual(result["selection"][key], value)

    def test_other_supported_cross_log_ids_and_correct_target_ids(self):
        for category, service, source, target, predicate in [
            ("process_creation", "security", 1, 4688, {"Image|endswith": "\\malware.exe"}),
            ("process_creation", "sysmon", 4688, 1, {"Image|endswith": "\\malware.exe"}),
            ("network_connection", "security", 3, 5156, {"SourceIp": "192.0.2.1"}),
            ("network_connection", "sysmon", 5156, 3, {"SourceIp": "192.0.2.1"}),
            ("wmi_event", "wmi", 21, 5861, {"Destination|contains": "malware"}),
        ]:
            with self.subTest(category=category, service=service):
                detection = {"selection": {"EventID": source, **predicate}, "condition": "selection"}
                result = self.convert(detection, category, service)["detection"]
                self.assertEqual(result[category]["EventID"], target)
                self.assertNotIn("EventID", result["selection"])
                detection["selection"]["EventID"] = target
                result = self.convert(detection, category, service)["detection"]
                self.assertEqual(result["selection"]["EventID"], target)

    def test_wmi_registration_subsets_are_not_widened_to_binding_events(self):
        for ids in [19, 20, [19, 20]]:
            with self.subTest(ids=ids):
                detection = {"selection": {"EventID": ids, "Destination|contains": "malware"}, "condition": "selection"}
                self.assertIsNone(self.convert(detection, "wmi_event", "wmi"))
        result = self.convert({"selection": {"EventID": 5861, "Destination|contains": "malware"},
                               "condition": "selection"}, "wmi_event", "sysmon")["detection"]
        self.assertEqual(result["selection"]["EventID"], 21)

    def test_category_selector_name_collision_and_aggregation(self):
        for condition in ["registry_event", "registry_event | count() by TargetObject > 3"]:
            with self.subTest(condition=condition):
                result = self.convert({"registry_event": {"EventID": [12, 13], "TargetObject|contains": "malware"},
                                       "condition": condition})["detection"]
                self.assertEqual(result["logsource_mapping_registry_event"]["EventID"], 4657)
                self.assertNotIn("EventID", result["registry_event"])
                self.assertIn("logsource_mapping_registry_event and registry_event", result["condition"])

    def test_input_detection_is_not_mutated_and_unrestricted_rule_stays_unrestricted(self):
        detection = {"selection": {"TargetObject|contains": "malware"}, "condition": "selection"}
        original = copy.deepcopy(detection)
        result = self.convert(detection)["detection"]
        self.assertEqual(detection, original)
        self.assertNotIn("EventID", result["selection"])
