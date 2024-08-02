# Curation of Sigma Rules for Windows Event Logs

[**English**] | [\[日本語\]](README-Japanese.md)

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

# Table of Contents

- [Curation of Sigma Rules for Windows Event Logs](#curation-of-sigma-rules-for-windows-event-logs)
- [Table of Contents](#table-of-contents)
- [About this repository](#about-this-repository)
- [The challenges with upstream Sigma rules for Windows event logs](#the-challenges-with-upstream-sigma-rules-for-windows-event-logs)
  - [About the `logsource` field](#about-the-logsource-field)
    - [Service fields](#service-fields)
      - [Single channel example:](#single-channel-example)
      - [Multiple channel example:](#multiple-channel-example)
      - [Current list of service mappings](#current-list-of-service-mappings)
      - [Service mapping sources](#service-mapping-sources)
    - [Category fields](#category-fields)
    - [Category field example:](#category-field-example)
      - [Current list of category mappings](#current-list-of-category-mappings)
      - [Category mapping sources](#category-mapping-sources)
- [Benefits and challenges of abstracting the log source](#benefits-and-challenges-of-abstracting-the-log-source)
  - [Log source abstraction benefits:](#log-source-abstraction-benefits)
  - [Log source abstraction challenges:](#log-source-abstraction-challenges)
- [Conversion example](#conversion-example)
  - [Before conversion](#before-conversion)
  - [After conversion](#after-conversion)
- [Conversion commonalities](#conversion-commonalities)
- [Conversion limitations](#conversion-limitations)
- [Process creation event comparison and rule conversion](#process-creation-event-comparison-and-rule-conversion)
- [](#)
- [Pre-converted Sigma rules](#pre-converted-sigma-rules)
- [Tool Environment](#tool-environment)
- [Tool usage](#tool-usage)
- [Authors](#authors)


# About this repository

This repository contains documentation of how Yamato Security curates upstream [Sigma](https://github.com/SigmaHQ/sigma) rules for Windows event logs into a more usable form by deabstracting the `logsource` field and filtering out any rules that are determined to be unsable or hard to use with the tool `sigma-to-hayabusa-converter.py`.
This tool is used mainly for creating the curated Sigma ruleset hosted at [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) which is used by [Hayabusa](https://github.com/Yamato-Security/hayabusa) and [Velociraptor](https://github.com/Velocidex/velociraptor)
We hope this information may be useful for other projects that are trying to use Sigma rules for detecting attacks in Windows event logs.

# The challenges with upstream Sigma rules for Windows event logs

The main challenge for creating a native Sigma rule parser for Windows event logs, in our experience, has been to support the `logsource` field.
Currently, this is one of the few things that Hayabusa does not support natively yet as this is still very complex and a work in progress.
For the time being, we are getting around this by converting the upstream rules into an easier to use format as explained in detail in this document.

## About the `logsource` field

In Sigma rules for Windows event logs, the `product` field is set to `windows` followed by either a `service` field or `category` field.

`service` field example:
```
logsource:
    product: windows
    service: application
```

`category` field example:
```
logsource:
    product: windows
    category: process_creation
```

### Service fields

`service` fields are relatively simple to handle and tells whatever backend using the Sigma rule to search for a single channel or multiple channels based on the `Channel` field in the Windows XML event log.

#### Single channel example:
`service: application` is the same thing as adding a selection condition of `Channel: Application` to the Sigma rule.

#### Multiple channel example:
`service: applocker` currently creates the most amount of multiple channels to search through as Applocker will save information in four different logs. In order to properly search just the Applocker logs, the following condition needs to be added to the Sigma rule logic:
```
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
``` 

#### Current list of service mappings

| Service                                 | Channel                                                                                               |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------|
| application                             | Application                                                                                           |
| application-experience                  | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                               | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                        | Microsoft-Windows-AppModel-Runtime/Admin                                                              |
| appxpackaging-om                        | Microsoft-Windows-AppxPackaging/Operational                                                           |
| bits-client                             | Microsoft-Windows-Bits-Client/Operational                                                             |
| capi2                                   | Microsoft-Windows-CAPI2/Operational                                                                   |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                               |
| codeintegrity-operational               | Microsoft-Windows-CodeIntegrity/Operational                                                           |
| diagnosis-scripted                      | Microsoft-Windows-Diagnosis-Scripted/Operational                                                      |
| dhcp                                    | Microsoft-Windows-DHCP-Server/Operational                                                             |
| dns-client                              | Microsoft-Windows-DNS Client Events/Operational                                                       |
| dns-server                              | DNS Server                                                                                            |
| dns-server-analytic                     | Microsoft-Windows-DNS-Server/Analytical                                                               |
| driver-framework                        | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                               |
| firewall-as                             | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                     |
| hyper-v-worker                          | Microsoft-Windows-Hyper-V-Worker                                                                      |
| kernel-event-tracing                    | Microsoft-Windows-Kernel-EventTracing                                                                 |
| kernel-shimengine                       | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic       |
| ldap_debug                              | Microsoft-Windows-LDAP-Client/Debug                                                                   |
| lsa-server                              | Microsoft-Windows-LSA/Operational                                                                     |
| microsoft-servicebus-client             | Microsoft-ServiceBus-Client                                                                           |
| msexchange-management                   | MSExchange Management                                                                                 |
| ntfs                                    | Microsoft-Windows-Ntfs/Operational                                                                    |
| ntlm                                    | Microsoft-Windows-NTLM/Operational                                                                    |
| openssh                                 | OpenSSH/Operational                                                                                   |
| powershell                              | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                  |
| powershell-classic                      | Windows PowerShell                                                                                    |
| printservice-admin                      | Microsoft-Windows-PrintService/Admin                                                                  |
| printservice-operational                | Microsoft-Windows-PrintService/Operational                                                            |
| security                                | Security                                                                                              |
| security-mitigations                    | Microsoft-Windows-Security-Mitigations*                                                               |
| shell-core                              | Microsoft-Windows-Shell-Core/Operational                                                              |
| smbclient-connectivity                  | Microsoft-Windows-SmbClient/Connectivity                                                              |
| smbclient-security                      | Microsoft-Windows-SmbClient/Security                                                                  |
| system                                  | System                                                                                                |
| sysmon                                  | Microsoft-Windows-Sysmon/Operational                                                                  |
| taskscheduler                           | Microsoft-Windows-TaskScheduler/Operational                                                           |
| terminalservices-localsessionmanager    | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                    |
| vhdmp                                   | Microsoft-Windows-VHDMP/Operational                                                                   |
| wmi                                     | Microsoft-Windows-WMI-Activity/Operational                                                            |
| windefend                               | Microsoft-Windows-Windows Defender/Operational                                                        |


#### Service mapping sources

We have created YAML mapping files for services to channel names which we periodcially maintain and host in this repository.
They are based on the service mapping information from [https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml) as although this does not seem to be an offical generic config file for people to use, it seems to be the most up-to-date.

### Category fields

Most `category` fields will just add a condition to check for certain event IDs in the `EventID` field in addition to searching for a specific `Channel`.
The category names are mostly based off of [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) events with some additional categories for built-in PowerShell logs and Windows Defender.

### Category field example:

```
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

#### Current list of category mappings

| Category                     | Service             | EventIDs                                        |
|------------------------------|---------------------|-------------------------------------------------|
| antivirus                    | windefend           | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change             | sysmon              | 24                                              |
| create_remote_thread         | sysmon              | 8                                               |
| create_stream_hash           | sysmon              | 15                                              |
| dns_query                    | sysmon              | 22                                              |
| driver_load                  | sysmon              | 6                                               |
| file_block_executable        | sysmon              | 27                                              |
| file_block_shredding         | sysmon              | 28                                              |
| file_change                  | sysmon              | 2                                               |
| file_creation                | sysmon              | 11                                              |
| file_delete                  | sysmon              | 23, 26                                          |
| file_delete_detected         | sysmon              | 26                                              |
| file_executable_detected     | sysmon              | 29                                              |
| image_load                   | sysmon              | 7                                               |
| **network_connection**       | sysmon              | 3                                               |
| **network_connection**       | security            | 5156                                            |
| pipe_created                 | sysmon              | 17, 18                                          |
| process_access               | sysmon              | 10                                              |
| **process_creation**         | sysmon              | 1                                               |
| **process_creation**         | security            | 4688                                            |
| process_tampering            | sysmon              | 25                                              |
| process_termination          | sysmon              | 5                                               |
| ps_classic_provider_start    | powershell-classic  | 600                                             |
| ps_classic_start             | powershell-classic  | 400                                             |
| ps_module                    | powershell          | 4103                                            |
| ps_script                    | powershell          | 4104                                            |
| raw_access_thread            | sysmon              | 9                                               |
| **registry_add**             | sysmon              | 12                                              |
| **registry_add**             | security            | 4657                                            |
| registry_delete              | sysmon              | 12                                              |
| **registry_event**           | sysmon              | 12, 13, 14                                      |
| **registry_event**           | security            | 4657                                            |
| registry_rename              | sysmon              | 14                                              |
| **registry_set**             | sysmon              | 13                                              |
| **registry_set**             | security            | 4657                                            |
| sysmon_error                 | sysmon              | 255                                             |
| sysmon_status                | sysmon              | 4, 16                                           |
| wmi_event                    | sysmon              | 19, 20, 21                                      |

You may have noticed that the same `category` can use multiple services and event IDs (**※indicated in bold**). 
That means that it is possible to use some Sigma rules designed for `sysmon` with similar built-in Windows `security` event logs if the fields that the rule uses also exist in the built-in event log.
In that case, the field names and sometimes also the values may need to be converted to match the field names and values of the built-in `security` event log.
The details of how we do this conversion and the compatibility between `sysmon` logs and `security` logs are explained later in this document.

#### Category mapping sources

The YAML mapping files for categories are also hosted in this repository and are also based on the information from [https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml).

# Benefits and challenges of abstracting the log source

There are benefits and challenges due to abstracting the log source and creating mappings for different `Channel`, `EventID` and fields on the backend.

## Log source abstraction benefits:

1. It may be easier to convert the `Channel` and `EventID` fieldnames to the proper backend field names when converting Sigma rules to other backend queries.
2. It is possible to consolidate two rules into one rule. For example, process creation events can be logged in `Sysmon 1` as well as `Security 4688`. Instead of writing two rules that look at different channels, event IDs and fields but otherwise contain the same logic, it is possible to standardize the fields to what sysmon uses and then later have a backend converter to add the `Channel` and `EventID` fields as well as convert other field information if necessary. This makes maintenance of rules easier as there are less rules to maintain.
3. Although very rare, if a log source starts logging its data if a different `Channel` or `EventID`, only the mapping logic needs to be updated instead of updating all Sigma rules making maintence easier.

## Log source abstraction challenges:

1. What happens if the original Sigma rule based on Sysmon uses a field that does not exist in the built-in logs for filtering out false positives? Should you create the rule anyways prioritizing possible detection or ignore it to prioritize less false positives? Ideally, two rules would need to be created with different `severity`, `status`, and false positive information in order for the user to handle it better.
2. It makes filtering rules more difficult as you cannot just filter based on `Channel` or `EventID` fields in the `.yml` file or the rule's file path if the file has not been created yet due to being a derived rule for a built-in log instead of the original Sysmon rule. Also, as the rule ID is the same, you cannot filter on rule IDs.
3. It makes confirming the alert more difficult when the alert comes from a rule for built-in logs that was derived from a Sysmon log. The field names and values will not match up so the analyst needs to understand and memorize the somewhat complex conversion process.
4. It makes creating the backend logic more complex.

While we cannot do anything about the first issue besides create and maintain new rules if there is significant use case that justifies the effort, in order to address issues 2-4, we have decided to de-abstract the `logsource` field and create two sets of rules for any rule that can produce multiple rules. Rules that can detect attacks in built-in logs are outputted into the `builtin` directory and rules for Sysmon are outputted into the `sysmon` directory.

# Conversion example

Here is a simple example to better understand the conversion process. 

## Before conversion
Sigma rule:
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

## After conversion
Hayabusa-compatible rule for Sysmon logs:
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

Hayabusa-compatible rule for Windows built-in logs:
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

As you can see, two rules have been created, one for Sysmon 1 logs and one for the built-in Security 4688 logs.
A new `process_creation` condition has been added with the channel and event ID information and the condition has been added to the `condition` field to require this condition.
Also, the original `Image` field name has been changed to `NewProcessName`.

# Conversion commonalities

Before explaining in details on how we convert specific categories, we will explain any part of the conversion that applies to all rules.

1. Any rule that has an ID in `ignore-uuid-list.txt` will be ignored. Currently we are only ignoring two rules that cause false positives on Windows defender because they have keywords like `mimikatz` in them.

2. "Placeholder" rules are ignored because they cannot be used as-is. These are rules that are placed in the `rules-placeholder` folder in the Sigma repository [here](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/).

3. Rules that use incompatible field modifiers. Currently Hayabusa supports the majority of field modifiers shown here so will not output any rule that uses a modifier besides these in order to avoid parsing errors:

    * all
    * base64
    * base64offset
    * cidr
    * contains
    * endswith
    * endswithfield
    * equalsfield
    * re
    * startswith
    * windash

4. Rules will syntax errors will not be converted.

5. Since we are adding `Channel` and `EventID` information to rules, we create a new UUIDv4 ID by using the MD5 hash of the original ID and specify the original ID in the `related` field and mark the `type` as `derived`. For rules that can be converted to multiple rules (`sysmon` and `builtin`), we need to create new rule IDs for the derived `builtin` rules as well. In order to do this, we calculate a MD5 hash of the `sysmon` rule ID and use that for the UUIDv4 ID. Here is an example:

    Original Sigma rule:
    ```
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    New `sysmon` rule:
    ```
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    New `builtin` rule:
    ```
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

6. Rules that detect things in built-in Windows event logs are outputted to the `builtin` directory while the rules that rely on Sysmon logs are outputted to the `sysmon` directory with the sub-directories matching the directories in the upstream Sigma repository.

# Conversion limitations

There is only one bug at the moment in that comment lines in Sigma rules will not included in the outputted rules unless the comments follow some source code.

# Process creation event comparison and rule conversion

* Category: `process_creation`
* Sysmon
  * Channel: `Microsoft-Windows-Sysmon/Operational`
  * Event ID: `1`
* Built-in log
  * Channel: `Security`
  * Event ID: `4688`



# 

# Pre-converted Sigma rules

Sigma rules are curated in the way described in this document by de-abstracting the `logsource` field and hosted in the [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) repository under the `sigma` folder.

# Tool Environment
If you want to locally convert Sigma rules into Hayabusa-compatible format, you first need to install [Poetry](https://python-poetry.org/).
Please refer to the official documentation for Poetry installation at the following link:
https://python-poetry.org/docs/#installation

# Tool usage

`sigma-to-hayabusa-converter.py` is our main tool to convert the `logsource` field of Sigma rules to Hayabusa format.
Perform the following tasks to run it.


1. `git clone https://github.com/SigmaHQ/sigma.git`
2. `git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git`
3. `cd sigma-to-hayabusa-converter`
4. `poetry install --no-root`
5. `poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules`

After executing the commands above, the rules converted to Hayabusa-compatible format will be output to the `./converted_sigma_rules` directory.

# Authors

This document was created by Zach Mathis (@yamatosecurity) and translated to Japanese by Fukusuke Takahashi.

The research for the registry and network connection category differences as well as the `sigma-to-hayabusa-converter.py` tool implementation and maintenence is done by Fukusuke Takahashi.

The original conversion tool that relied on the now-deprecated sigmac tool was implemented by ItiB (@itiB_S144) and James Takai / hachiyone(@hach1yon).