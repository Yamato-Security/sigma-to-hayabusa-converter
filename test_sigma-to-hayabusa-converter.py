from unittest import TestCase
from tempfile import TemporaryDirectory
import subprocess

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
    def test_ignore_7045_unusual_client_rule_but_keep_security_variant(self):
        script_dir = Path(__file__).resolve().parent
        with TemporaryDirectory() as temp:
            source = Path(temp) / "rules"
            output = Path(temp) / "output"
            source.mkdir()
            (source / "system.yml").write_text("""\
title: Service Installed By Unusual Client - System
id: 71c276aa-49cd-43d2-b920-2dcd3e6962d5
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: Service Control Manager
        EventID: 7045
        ProcessId: 0
    condition: selection
""", encoding="utf-8")
            (source / "security.yml").write_text("""\
title: Service Installed By Unusual Client - Security
id: c4e92a97-a9ff-4392-9d2d-7a4c642768ca
logsource:
    product: windows
    service: security
detection:
    selection_eid:
        EventID: 4697
    selection_pid:
        - ClientProcessId: 0
        - ParentProcessId: 0
    condition: all of selection_*
""", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script_dir / "sigma-to-hayabusa-converter.py"),
                 "-r", str(source), "-o", str(output)],
                cwd=script_dir, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("71c276aa-49cd-43d2-b920-2dcd3e6962d5", result.stdout + result.stderr)
            self.assertIn("Conversion skipped", result.stdout + result.stderr)
            files = list(output.rglob("*.yml"))
            self.assertEqual(len(files), 1, [str(path) for path in files])
            converted = create_obj(None, str(files[0]))[0]
            self.assertEqual(converted["title"], "Service Installed By Unusual Client - Security")
            self.assertEqual(converted["detection"]["selection_pid"],
                             [{"ClientProcessId": 0}, {"ParentProcessId": 0}])
            self.assertIn({"id": "c4e92a97-a9ff-4392-9d2d-7a4c642768ca", "type": "derived"}, converted["related"])

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
