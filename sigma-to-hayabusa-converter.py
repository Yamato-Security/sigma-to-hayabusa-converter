import argparse
import copy
import fnmatch
import hashlib
import logging
import os
import re
import shutil
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from functools import reduce
from io import StringIO
from pathlib import Path
from typing import Union, Optional

import ruamel.yaml

FORMAT = '[%(levelname)-2s:%(filename)s:%(lineno)d] %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)
LOGGER = logging.getLogger(__name__)

WINDOWS_SYSMON_PROCESS_CREATION_FIELDS = ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion",
                                          "Description", "Product", "Company", "OriginalFileName", "CommandLine",
                                          "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId",
                                          "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId",
                                          "ParentImage", "ParentCommandLine", "ParentUser"]

WINDOWS_SECURITY_PROCESS_CREATION_FIELDS = ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
                                            "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId",
                                            "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName",
                                            "TargetLogonId", "ParentProcessName", "MandatoryLabel"]

WINDOWS_SYSMON_REGISTRY_EVENT_FIELDS = ["EventType", "UtcTime", "ProcessId", "ProcessGuid", "Image", "TargetObject",
                                        "Details", "NewName"]
WINDOWS_SECURITY_REGISTRY_EVENT_FIELDS = ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
                                          "ObjectName", "ObjectValueName", "HandleId", "OperationType", "OldValueType",
                                          "OldValue", "NewValueType", "NewValue", "ProcessId", "ProcessName"]

WINDOWS_SYSMON_NETWORK_EVENT_FIELDS = ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "Protocol",
                                       "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort",
                                       "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname",
                                       "DestinationPort", "DestinationPortName", "CommandLine", "ParentImage"]
WINDOWS_SECURITY_NETWORK_EVENT_FIELDS = ["ProcessID", "Application", "Protocol", "Direction", "SourceAddress",
                                         "SourcePort", "DestAddress", "DestPort", "FilterRTID", "LayerName",
                                         "LayerRTID", "RemoteUserID", "RemoteMachineID"]

INTEGRITY_LEVEL_VALUES = {
    "LOW": "S-1-16-4096",
    "MEDIUM": "S-1-16-8192",
    "HIGH": "S-1-16-12288",
    "SYSTEM": "S-1-16-16384"
}

OPERATION_TYPE_VALUES = {
    "CreateKey": "%%1904",
    "SetValue": "%%1905",
    "DeleteValue": "%%1906",
    "RenameKey": "%%1905"
}

CONNECTION_INITIATED_VALUES = {
    "true": "%%14593",
    "false": "%%14592"
}

CONNECTION_PROTOCOL_VALUES = {
    "tcp": "6",
    "udp": "17"
}

IGNORE_UUID_LIST = [line.split('#')[0].strip() for line in Path('ignore-uuid-list.txt').read_text().splitlines() if
                    not line.strip().startswith('#') and line.split('#')[0].strip() != '']


def get_terminal_keys_recursive(dictionary, keys=None) -> list[str]:
    """
    dictの末端キーを再帰的にリストアップ
    """
    if keys is None:
        keys = []
    for key, value in dictionary.items():
        keys.append(key)
        if isinstance(value, dict):
            get_terminal_keys_recursive(value, keys)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    get_terminal_keys_recursive(item, keys)
    return keys


def convert_special_val(key: str, value: str | list[str]) -> str | list[str]:
    """
    ProcessIdとIntegrityLevelとOperationTypeはValueの形式が違うため、変換する
    """
    if key == "ProcessId" or key == "NewProcessId":
        return str(hex(int(value))) if isinstance(value, int) else [str(hex(int(v))) for v in value]
    elif key == "MandatoryLabel":
        return str(INTEGRITY_LEVEL_VALUES.get(value.upper())) if isinstance(value, str) else [
            str(INTEGRITY_LEVEL_VALUES.get(v.upper())) for v in value]
    elif key == "OperationType":
        return OPERATION_TYPE_VALUES.get(value)
    elif key == "ObjectName":
        if isinstance(value, str):
            return value.replace("HKLM", r"\REGISTRY\MACHINE").replace("HKU", r"\REGISTRY\USER")
        elif isinstance(value, list):
            return [x.replace("HKLM", r"\REGISTRY\MACHINE").replace("HKU", r"\REGISTRY\USER") for x in value]
    elif key == "Direction":
        return str(CONNECTION_INITIATED_VALUES.get(value, value))
    elif key == "Application":
        if isinstance(value, str):
            return value.replace("C:", "\\device\\harddiskvolume?")
        elif isinstance(value, list):
            return [x.replace("C:", "\\device\\harddiskvolume?") for x in value]
    elif key == "Protocol":
        return str(CONNECTION_PROTOCOL_VALUES.get(value, value))
    return value


def assign_uuid_for_convert_rules(obj: dict, logsource_hash: str) -> dict:
    if "id" not in obj:
        return dict(obj)
    original_uuid = obj["id"]
    if original_uuid in IGNORE_UUID_LIST:
        msg = f"This rule has UUIDs to be excluded [{original_uuid}]. Conversion skipped."
        raise Exception(msg)
    hash_bytes = hashlib.md5((original_uuid + logsource_hash).encode()).digest()
    new_obj = dict()
    new_obj["title"] = obj["title"]
    new_obj["id"] = str(uuid.UUID(bytes=hash_bytes))
    for k, v in obj.items():
        if k == "id":
            if "related" not in obj:
                new_obj["related"] = [{"id": original_uuid, "type": "derived"}]
            else:
                related = obj["related"]
                if not [x for x in related if x["id"] == original_uuid]:
                    related.append({"id": original_uuid, "type": "derived"})
                new_obj["related"] = related
        elif k != "related":
            new_obj[k] = v  # idの次の行に挿入するためすべて代入しなおす
    return new_obj


def referenced_rule_is_uuid(obj: dict) -> bool:
    if not ("correlation" in obj and "rules" in obj["correlation"]):
        return False
    try:
        for id in obj["correlation"]["rules"]:
            uuid.UUID(id)
            return True
    except ValueError:
        return False


@dataclass(frozen=True)
class LogSource:
    category: Optional[str]
    service: str
    channel: Union[str, list[str]]
    event_id: Optional[Union[int, list[int]]]

    def __hash__(self):
        return hash((self.category, self.service, tuple(self.channel)))

    def get_identifier_for_detection(self, keys: list[str]) -> str:
        new_identifier = ""
        if not self.category:
            new_identifier = self.service.replace("-", "_")
        else:
            new_identifier = self.category.replace("-", "_")
        if any([True for key in keys if key == new_identifier]):
            new_identifier = "logsource_mapping_" + new_identifier
        return new_identifier

    def get_detection(self) -> dict:
        """
        logsourceをdetection用に変換
        """
        if self.event_id:
            return {"EventID": self.event_id, "Channel": self.channel}
        return {"Channel": self.channel}

    def get_condition(self, condition_str, keys: list[str], field_map: dict[str, str]) -> str:
        """
        detectionに追加したlogsourceの条件をconditionにも追加
        """
        if match := re.search(r"([^|].*?)(\s?\| count\(.*)", condition_str):
            # 集計条件はパイプの前までを（）で囲んでand
            cond_before_pipe = f"({self.get_identifier_for_detection(keys)} and {match.group(1)})"
            cond_after_pipe = match.group(2)
            if self.need_field_conversion():
                for field in field_map.keys():
                    cond_after_pipe = cond_after_pipe.replace(field, field_map[field])
            return cond_before_pipe + cond_after_pipe
        if ' ' not in condition_str:
            return f"{self.get_identifier_for_detection(keys)} and {condition_str}"
        return f"{self.get_identifier_for_detection(keys)} and ({condition_str})"

    def need_field_conversion(self) -> bool:
        """
        process_creation/registry_xx/network_connectionルールのSysmon/Securityイベント用のフィールド変換要否を判定
        """
        if self.category == "antivirus":
            return True
        if self.category == "process_creation" and self.event_id == 4688:
            return True
        if (
                self.category == "registry_set" or self.category == "registry_add" or self.category == "registry_event" or self.category == "registry_delete") and self.event_id == 4657:
            return True
        if self.category == "network_connection" and self.event_id == 5156:
            return True
        if self.category == "wmi_event" and self.event_id == 5861:
            return True
        return False

    def is_detectable_fields(self, keys, func) -> bool:
        common_fields = ["CommandLine", "ProcessId"]
        if self.category == "network_connection" and (self.event_id == 5156 or self.event_id == 3):
            common_fields = ["ProcessId", "SourcePort", "Protocol"]
        keys = [re.sub(r"\|.*", "", k) for k in keys]
        keys = [k for k in keys if k not in common_fields]
        if not keys:
            return True
        elif self.event_id == 4688:
            return not func([k in WINDOWS_SYSMON_PROCESS_CREATION_FIELDS for k in keys])
        elif self.event_id == 1:
            return not func([k in WINDOWS_SECURITY_PROCESS_CREATION_FIELDS for k in keys])
        elif self.event_id == 4657:
            return not func([k in WINDOWS_SYSMON_REGISTRY_EVENT_FIELDS for k in keys])
        elif self.event_id == 12 or self.event_id == 13 or self.event_id == 14:
            return not func([k in WINDOWS_SECURITY_REGISTRY_EVENT_FIELDS for k in keys])
        elif self.event_id == 5156:
            return not func([k in WINDOWS_SYSMON_NETWORK_EVENT_FIELDS for k in keys])
        elif self.event_id == 3:
            return not func([k in WINDOWS_SECURITY_NETWORK_EVENT_FIELDS for k in keys])
        return True

    def is_detectable(self, obj: dict, check_only_selection=False) -> bool:
        """
        process_creation/registry_xx/network_connectionルールののSysmon/Securityイベント用変換後フィールドの妥当性チェック
        """
        if self.category != "process_creation" and self.category != "registry_set" and self.category != "registry_add" and self.category != "registry_event" and self.category != "registry_delete" and self.category != "network_connection":
            return True
        for key in obj.keys():
            if check_only_selection and key != "selection":
                continue
            if key in ["condition", "process_creation", "timeframe", "registry_set", "registry_add", "registry_event",
                       "registry_delete", "network_connection"]:
                continue
            val_obj = obj[key]
            is_detectable = True
            if isinstance(val_obj, dict):
                keys = val_obj.keys()
                is_detectable = self.is_detectable_fields(keys, any)
            elif isinstance(val_obj, list):
                if not [v for v in val_obj if isinstance(v, dict)]:
                    continue
                keys = [list(k.keys()) for k in val_obj]
                keys = reduce(lambda a, b: a + b, keys)
                is_detectable = self.is_detectable_fields(keys, all)
            if not is_detectable:
                return False
        return True


@dataclass(frozen=True)
class LogsourceConverter:
    sigma_path: str
    logsource_map: dict[str, list[LogSource]]
    field_map: dict[str, dict]
    sigma_converted: list[tuple[bool, dict]] = field(default_factory=list)
    sigma_correlation_converted: list[tuple[bool, list[dict]]] = field(default_factory=list)

    def transform_field(self, category: str, obj: dict, original_field):
        """
        field_mapの内容でfiled名を変換する(category=process_creation/antivirus以外は変換されない)
        """
        for rewrite_filed in self.field_map[category].keys():
            if original_field == rewrite_filed:
                new_key = self.field_map[category][original_field]
                val = convert_special_val(new_key, obj.pop(original_field))
                obj[new_key] = val
            elif original_field.startswith(rewrite_filed) and original_field.replace(rewrite_filed, "")[0] == "|":
                new_key = self.field_map[category][rewrite_filed] + original_field.replace(rewrite_filed, "")
                val = convert_special_val(self.field_map[category][rewrite_filed], obj.pop(original_field))
                obj[new_key] = val
        for k, v in obj.copy().items():
            if k == "SubjectUserName":
                obj[k] = re.sub(r".*\\", "", v)
                obj["SubjectDomainName"] = re.sub(r"\\.*", "", v)
            else:
                obj[k] = v

    def transform_field_recursive(self, category: str, obj: dict, need_field_conversion: bool) -> dict:
        """
        dictを再帰的に探索し、field_mapの内容でfiled名を変換する(category=process_creation以外は変換されない)
        """
        if isinstance(obj, dict):
            for field_name, val in list(obj.items()):
                if not need_field_conversion:
                    return obj
                self.transform_field(category, obj, field_name)
                if isinstance(val, dict):
                    self.transform_field_recursive(category, val, need_field_conversion)
                elif isinstance(val, list):
                    for item in val:
                        self.transform_field_recursive(category, item, need_field_conversion)
        elif isinstance(obj, list):
            for item in obj:
                self.transform_field_recursive(category, item, need_field_conversion)
        return obj

    def get_logsources(self, obj: dict) -> list[LogSource]:
        """
        sigmaルールのlogsourceブロックの内容をLogSourceオブジェクトに変換。categoryによっては、複数LogSourceに変換する場合もある
        """
        if 'logsource' not in obj:
            return []
        elif 'service' in obj['logsource']:
            logsources = self.logsource_map.get(obj['logsource']['service'])
            if logsources:
                return logsources
            msg = f"This rule inconvertible service:[{obj['logsource']['service']}]. Conversion skipped."
            raise Exception(msg)
        elif 'category' in obj['logsource']:
            category = obj['logsource']['category']
            logsources = self.logsource_map.get(category)
            if logsources:
                return logsources
            msg = f"This rule has inconvertible service: [{category}]. Conversion skipped."
            raise Exception(msg)
        return []

    def check_and_get_logsource(self, obj: dict) -> list[LogSource]:
        if obj.get("correlation", {}):
            correlation_type = obj.get("correlation", {}).get("type", {})
            if correlation_type in ["event_count", "value_count"]:
                new_obj = copy.deepcopy(obj)
                if 'ruleType' not in new_obj:
                    new_obj['ruletype'] = 'Sigma'
                self.sigma_converted.append((False, new_obj))
            else:
                LOGGER.error(f"This rule has unsupported correlation type:[{correlation_type}]. Conversion skipped.")
            return []
        keys = get_terminal_keys_recursive(obj["detection"], [])
        modifiers = {re.sub(r".*\|", "", k) for k in keys if "|" in k}
        convertible = ["all", "base64", "base64offset", "cidr", "contains", "endswith", "endswithfield", "equalsfield", "cased", "exists", "expand",
                       "re", "i", "m", "s", "startswith", "windash", "fieldref", "gt", "gte", "lt", "lte", "utf16", "utf16be", "utf16le", "wide"]
        if modifiers and [m for m in modifiers if m not in convertible]:
            LOGGER.error(f"This rule has incompatible field: {obj['detection']}. Conversion skipped.")
            return []
        con = obj['detection']['condition']
        if '%' in con or '->' in con or " near " in con:
            LOGGER.error(
                f"Error while converting rule [{self.sigma_path}]: Invalid character in condition [{con}] file [{self.sigma_path}]. Conversion skipped.")
            return []
        logsources = self.get_logsources(obj)
        if not logsources:
            new_obj = copy.deepcopy(obj)
            if "ruleType" not in new_obj:
                new_obj['ruletype'] = 'Sigma'
            self.sigma_converted.append((False, new_obj))
            return []
        return logsources

    def convert_rule(self, obj: dict, ls: LogSource) -> dict | None:
        new_obj = assign_uuid_for_convert_rules(obj, str(ls))
        if ls.service == "sysmon":
            if "tags" not in new_obj:
                new_obj["tags"] = ["sysmon"]
            elif "sysmon" not in new_obj["tags"]:
                tags = new_obj["tags"].copy()
                tags.append("sysmon")
                new_obj["tags"] = tags
        elif ls.category == "antivirus":
            new_obj['logsource']["product"] = "windows"
            new_obj['logsource']["service"] = ls.service
        if "tags" in new_obj and any('_' in tag for tag in new_obj["tags"]):
            new_obj["tags"] = [tag.replace("_", "-") for tag in new_obj["tags"]]
        detection = copy.deepcopy(new_obj['detection'])
        new_obj['detection'] = dict()
        new_obj['detection'][ls.get_identifier_for_detection(list(detection.keys()))] = ls.get_detection()
        for key, val in detection.items():
            key = re.sub(r"\.", "_", key)
            val = self.transform_field_recursive(ls.category, val, ls.need_field_conversion())
            new_obj['detection'][key] = val
        cond = str(new_obj['detection']['condition'])
        if (cond.endswith("selection") or "selection and " in cond) and not ls.is_detectable(new_obj['detection'], True):
            LOGGER.error(
                f"Error while converting rule [{self.sigma_path}]: This rule has incompatible field: {new_obj['detection']}. Conversion skipped.")
            return None
        if " of " not in cond and not ls.is_detectable(new_obj['detection']):
            LOGGER.error(
                f"Error while converting rule [{self.sigma_path}]: This rule has incompatible field: {new_obj['detection']}. Conversion skipped.")
            return None
        field_map = self.field_map[ls.category] if ls.category in self.field_map else dict()
        new_obj['detection']['condition'] = ls.get_condition(new_obj['detection']['condition'],
                                                             list(detection.keys()), field_map)
        if ls.need_field_conversion() and "fields" in new_obj:
            fields = new_obj['fields']
            converted_fields = [field_map[f] for f in fields if f in field_map]
            not_converted_fields = [f for f in fields if f not in field_map]
            new_obj['fields'] = converted_fields + not_converted_fields
        if "ruletype" not in new_obj:
            new_obj['ruletype'] = 'Sigma'
        return new_obj

    def convert(self):
        """
        logsourceのcategory/serviceをlogsource_mapに基づき変換し、変換後の内容でdetectionブロックを更新する
        """
        obj_list = create_obj(base_dir=None, file_name=self.sigma_path)
        if len(obj_list) == 1:
            logsources = self.check_and_get_logsource(obj_list[0])
            if not logsources:
                return  # ログソースマッピングにないcategory/serviceのため、変換処理はスキップ
            for ls in logsources:
                new_obj = self.convert_rule(obj_list[0], ls)
                if not new_obj:
                    return
                if ls.service == "sysmon":
                    self.sigma_converted.append((True, new_obj))
                else:
                    self.sigma_converted.append((False, new_obj))
        else:
            # correlationルールかつ複数YAMLの場合の変換
            correlation = obj_list.pop(0)
            if "ruletype" not in correlation:
                correlation['ruletype'] = "Sigma"
            sysmon_converted = [correlation]
            builtin_converted = [correlation]
            sysmon_uuid_list = []
            builtin_uuid_list = []
            for obj in obj_list:
                logsources = self.check_and_get_logsource(obj)
                if not logsources:
                    return  # ログソースマッピングにないcategory/serviceのため、変換処理はスキップ
                for ls in logsources:
                    new_obj = self.convert_rule(obj, ls)
                    if not new_obj:
                        return
                    if ls.service == "sysmon":
                        if "id" in new_obj:
                            sysmon_uuid_list.append(new_obj["id"])
                        sysmon_converted.append(new_obj)
                    else:
                        if "id" in new_obj:
                            builtin_uuid_list.append(new_obj["id"])
                        builtin_converted.append(new_obj)
            if len(sysmon_converted) > 1:
                sysmon_converted[0] = assign_uuid_for_convert_rules(sysmon_converted[0], "sysmon")
                if referenced_rule_is_uuid(sysmon_converted[0]):
                    new_obj = copy.deepcopy(sysmon_converted[0])
                    new_obj["correlation"]["rules"] = sysmon_uuid_list
                    sysmon_converted[0] = new_obj
                self.sigma_correlation_converted.append((True, sysmon_converted))
            if len(builtin_converted) > 1:
                builtin_converted[0] = assign_uuid_for_convert_rules(builtin_converted[0], "security")
                if referenced_rule_is_uuid(builtin_converted[0]):
                    new_obj = copy.deepcopy(builtin_converted[0])
                    new_obj["correlation"]["rules"] = builtin_uuid_list
                    builtin_converted[0] = new_obj
                self.sigma_correlation_converted.append((False, builtin_converted))

    def dump_yaml(self, is_sysmon, objs, base_dir, out_dir):
        def represent_none(self, _):
            return self.represent_scalar('tag:yaml.org,2002:null', u'null')

        output_path = build_out_path(base_dir, out_dir, self.sigma_path, is_sysmon)
        with StringIO() as bs:
            yaml = ruamel.yaml.YAML()
            yaml.representer.add_representer(type(None), represent_none)
            yaml.width = 4096
            yaml.indent(mapping=4, sequence=6, offset=4)
            for i, obj in enumerate(objs):
                yaml.dump(obj, bs)
                if i < len(objs) - 1:
                    bs.write('---\n')
            return output_path, bs.getvalue()

    def dump_yml(self, base_dir: str, out_dir: str) -> list[tuple[str, str]]:
        res = []
        for is_sysmon, obj in self.sigma_converted:
            res.append(self.dump_yaml(is_sysmon, [obj], base_dir, out_dir))

        # 変換後のcorrelationルールをdump
        for is_sysmon, objs in self.sigma_correlation_converted:
            LOGGER.info(objs)
            res.append(self.dump_yaml(is_sysmon, objs, base_dir, out_dir))

        return res


def build_out_path(base_dir: str, out_dir: str, sigma_path: str, sysmon: bool) -> str:
    """
    入力ファイルのパスをもとに、出力用のファイルパスを生成する
    """
    if not base_dir:
        if sysmon:
            return str(Path(out_dir).joinpath(Path("sysmon")).joinpath(Path(sigma_path).name))
        return str(Path(out_dir).joinpath(Path("builtin")).joinpath(Path(sigma_path).name))
    new_path = sigma_path.replace(base_dir, '')
    new_path = new_path.replace('/windows', '')
    new_path = new_path.replace('/builtin', '')
    new_path = new_path.replace('/rules-compliance', '/compliance')
    new_path = new_path.replace('/rules-dfir', '/dfir')
    new_path = new_path.replace('/rules-emerging-threats', '/emerging-threats')
    new_path = new_path.replace('/rules-threat-hunting', '/threat-hunting')
    new_path = new_path.replace('/rules-placeholder', '/placeholder')
    new_path = new_path.replace('/rules', '')
    if sysmon:
        return out_dir + '/sysmon' + new_path
    return out_dir + '/builtin' + new_path


def create_obj(base_dir: Optional[str], file_name: str) -> list[dict]:
    """
    ymlファイルを読み込み、dictを作成
    """
    if base_dir:
        file_path = Path(base_dir).joinpath(file_name)
    else:
        file_path = Path(file_name)
    if not file_path.exists():
        LOGGER.error(f"file [{file_path}] does not exists.")
        sys.exit(1)
    try:
        with open(file_path, encoding="utf-8") as f:
            yaml = ruamel.yaml.YAML()
            d = list(yaml.load_all(f))
            LOGGER.debug(f"loading yaml [{file_path}] done successfully.")
            return d
    except Exception as e:
        LOGGER.error(f"Error while loading yml [{file_path}]: {e}")
        sys.exit(1)


def create_field_map(key: str, obj: dict) -> dict[str, dict]:
    """
    カテゴリcreate_process用のフィールド名をマッピングするdict作成
    """
    if key not in obj:
        LOGGER.error(f"invalid yaml. key[{key}] not found.")
        sys.exit(1)
    field_map = obj[key]
    return field_map


def create_service_map(obj: dict) -> dict[str, Union[str, list[str]]]:
    """
    service -> channel をマッピングするdictを作成
    """
    if 'logsources' not in obj:
        LOGGER.error("invalid yaml. key[logsources] not found.")
        sys.exit(1)
    service_to_channel = dict()
    for v in obj['logsources'].values():
        if 'service' in v.keys() and 'conditions' in v.keys():
            service_to_channel[v['service']] = v['conditions']['Channel']
    LOGGER.debug("create service map done.")
    return service_to_channel


def create_category_map(obj: dict, service_to_channel: dict[str, Union[str, list[str]]]) -> set[LogSource]:
    """
    category -> channel, event_id マッピングするLogSourceオブジェクトのSetを作成
    """
    if 'logsources' not in obj:
        LOGGER.error("invalid yaml. key[logsources] not found.")
        sys.exit(1)
    mapper = set()
    for v in obj['logsources'].values():
        if 'category' not in v:
            continue
        ls = LogSource(category=v['category'],
                       service=v['rewrite']['service'],
                       channel=service_to_channel[v['rewrite']['service']],
                       event_id=v['conditions']['EventID'])
        mapper.add(ls)
    LOGGER.debug("create category map done.")
    return mapper


def merge_category_map(service_map: dict, logsources_lst: list) -> dict[str, list[LogSource]]:
    """
    複数のymlファイルから作成したdictをマージして、categoryをマッピングするための1つのdictを作成
    """
    merged_map = defaultdict(list)
    for logsources in logsources_lst:
        for ls in logsources:
            merged_map[ls.category].append(ls)
    for k, v in service_map.items():
        merged_map[k].append(LogSource(category=None, service=k, channel=v, event_id=None))
    LOGGER.debug("create category map done.")
    return merged_map


def find_windows_sigma_rule_files(root: str, rule_pattern: str):
    """
    指定したディレクトリから変換対象のSigmaファイルのファイルパスを取得する
    """
    LOGGER.info("Start to collect target yml files path.")
    if Path(root).exists() and Path(root).is_file() and rule_pattern.replace("*", "") in root:
        yield root
    for dirpath, dirnames, filenames in os.walk(root):
        for filename in fnmatch.filter(filenames, rule_pattern):
            filepath = os.path.join(dirpath, filename)
            if not any(target in dirpath for target in ["rule", "deprecated", "unsupported"]):
                continue  # フォルダパスにrule/deprecated/unsupportedがつかないものは、Sigmaルールと関係ないため、除外
            try:
                with open(filepath, encoding="utf-8") as f:
                    yaml = ruamel.yaml.YAML()
                    data_lst = list(yaml.load_all(f))
                data = data_lst[0]
                if len(data_lst) == 1 and not data.get('correlation', {}):
                    if data.get('logsource', {}).get('category') != "antivirus" \
                            and data.get('logsource', {}).get('product') != 'windows':
                        LOGGER.debug(f"[{filepath}] has no windows rule. Conversion skipped.")
                        continue
                else:
                    if not data.get('correlation', {}):
                        LOGGER.debug(f"[{filepath}] has multiple yaml. Conversion skipped.")
                        continue
                yield filepath
            except Exception as e:
                LOGGER.error(f"Error while loading yml [{filepath}]: {e}")


if __name__ == '__main__':
    start_time = time.perf_counter()
    LOGGER.info("Start to logsource mapping sigma rules.")
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", help="Output dir. Default: ./hayabusa_rules", default="./hayabusa_rules")
    parser.add_argument("-r", "--rule_path", help="Target sigma dir or file path.", required=True)
    parser.add_argument("--rule_filter", help="Target file filter. Default: *.yml", default="*.yml")
    parser.add_argument("--debug", help="Debug mode.", action="store_true")
    args = parser.parse_args()

    if args.debug:
        LOGGER.setLevel(level=logging.DEBUG)
    LOGGER.debug(f"Args: output[{args.output}], rule_path[{args.rule_path}].")

    if not Path(args.rule_path).exists():
        LOGGER.error(f"Rule directory(file) [{args.rule_path}] does not exists.")
        sys.exit(1)

    if Path(args.output).exists():
        try:
            shutil.rmtree(args.output)
            LOGGER.info(f"Directory [{args.output}] deleted successfully.")
        except OSError as e:
            LOGGER.error(f"Error while deleting directory [{args.output}]: {e}")
            sys.exit(1)

    # category -> channel/event_id 変換のマッピングデータを作成
    script_dir = os.path.dirname(os.path.abspath(__file__))
    service2channel = create_service_map(create_obj(script_dir, "services-mapping.yaml")[0])
    sysmon_map = create_category_map(create_obj(script_dir, 'sysmon-category-mapping.yaml')[0], service2channel)
    win_audit_map = create_category_map(create_obj(script_dir, 'builtin-category-mapping.yaml')[0], service2channel)
    win_service_map = create_category_map(create_obj(script_dir, 'services-mapping.yaml')[0], service2channel)
    all_category_map = merge_category_map(service2channel,[sysmon_map, win_audit_map, win_service_map])
    process_creation_field_map = create_field_map("fieldmappings_process",
                                                  create_obj(script_dir, 'builtin-category-mapping.yaml')[0])
    registry_field_map = create_field_map("fieldmappings_registry", create_obj(script_dir,
                                                                               'builtin-category-mapping.yaml')[0])
    network_field_map = create_field_map("fieldmappings_network", create_obj(script_dir,
                                                                             'builtin-category-mapping.yaml')[0])
    antivirus_field_map = create_field_map("fieldmappings_antivirus", create_obj(script_dir, 'builtin-category-mapping.yaml')[0])

    wmi_field_map = create_field_map("fieldmappings_wmi", create_obj(script_dir, 'builtin-category-mapping.yaml')[0])

    field_map = {"process_creation": process_creation_field_map} | {"antivirus": antivirus_field_map} | {
        "registry_set": registry_field_map} | {"registry_add": registry_field_map} | {
                    "registry_event": registry_field_map} | {"registry_delete": registry_field_map} | {
                    "network_connection": network_field_map} | {"wmi_event": wmi_field_map}
    LOGGER.info("Loading logsource mapping yaml(sysmon/windows-audit/windows-services) done.")

    # Sigmaディレクトリから対象ファイルをリストアップ
    sigma_files = list(find_windows_sigma_rule_files(args.rule_path, args.rule_filter))
    LOGGER.info(f"Collecting target yml files path done. Start to convert [{len(sigma_files)}] files.")
    file_cnt = 0
    file_err_cnt = 0
    for sigma_file in sigma_files:
        try:
            lc = LogsourceConverter(sigma_file, all_category_map, field_map)
            lc.convert()  # Sigmaルールをマッピングデータにもとづき変換
            base_dir = args.rule_path if Path(args.rule_path).is_dir() else ""
            for out_path, parsed_yaml in lc.dump_yml(base_dir, args.output):  # dictをyml形式の文字列に変換
                p = Path(out_path)
                if not p.parent.exists():
                    os.makedirs(p.parent)
                p.write_text(parsed_yaml, encoding="utf-8")  # 変換後のSigmaルール(yml形式の文字列)をファイルに出力
                file_cnt += 1
                LOGGER.debug(f"Converted to [{out_path}] done.")
        except Exception as err:
            file_err_cnt += 1
            LOGGER.error(f"Error while converting rule [{sigma_file}]: {err}")
    end_time = time.perf_counter()
    LOGGER.info(
        f"[{file_cnt}] files created successfully.[{file_err_cnt}] files failed to convert. Created files were saved under [{args.output}].")
    LOGGER.info(f"Script took [{'{:.2f}'.format(end_time - start_time)}] seconds.")
