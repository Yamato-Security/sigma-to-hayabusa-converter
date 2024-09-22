# Changes

## v2.17.0 [2024/09/22]

- `|fieldref` modifier names are temporarily renamed to `equalsfield` in order to be used by the current versions of Hayabusa. (#24) (@fukusuket)

## v2.17.0 [2024/09/18]

- Support for built-in WMI event converstion. (#12) (@fukusuket)
  - Now, sigma rules with a category of `wmi_event` will have the following conversion take place:
    - The following condition is added
    ```
    EventID: 5861
    Channel: Microsoft-Windows-WMI-Activity/Operational
    ```
    - The field `Destination` will be renamed to `UserDataPossibleCause`.

## v2.17.0 [2024/09/16]

- Bug fix: Rules for built-in Windows event logs had the `sysmon` tag added to them by mistake. (#21) (@fukusuket)

## v2.16.0 [2024/08/15]

- Convert Sigma v1 tag format (`_`) to v2 format (`-`) for `deprecated` and `unsupported` rules. (#18) (@fukusuket)

## v2.16.0 [2024/08/02]

- Config files were consolidated and renamed. #11 (@fukusuket)
- Fixed derived rule IDs. #13 (@fukusuket)
- "Placeholder" rules are now ignored. #14 (@fukusuket)

## v2.16.0 [2024/07/30]

- We are now creating built-in Windows `Security 5156` rules for `category: network_connection` rules. Before, the rules would only detect `Sysmon 3` events. #10 (@fukusuket) 

## v2.16.0 [2024/06/25]

- Support for converting Sigma correlation rules with multiple rules inside a single `.yml` file. #9 (@fukusuket)

## v2.15.0 [2024/06/05]

- An ignore list `ignore-uuid-list.txt` was added to ignore the rules that cause false positives with Windows Defender. (#672) (@fukusuket)

## v2.15.0 [2024/06/04]

- The windash modifier (ex: `|windash|contains`) is now left as is and we do not convert these to more compatible rules now that Hayabusa supports windash natively as of version 2.15.0. (#646) (@fukusuket)

## v2.13.0 [2024/03/27]

- Updated the `proven_rules.txt` file. (@YamatoSecurity)

## v2.13.0 [2024/03/24]

- Newly created rules are assigned with new UUIDv4 IDs. (#629) (@fukusuket)
- Fixed a bug where `logsource_mapping.py` was creating rules with `near` conditions. (#632) (@fukusuket)
- Refactored `logsource_mapping.py` and adding unit tests. (#627) (@fukusuket)
- Updated `exclude_rules.txt`. (@fukusuket)

## v2.13.0 [2024/03/22]

- Bug fix: the `null` keyword was converted to an empty string. This may have been a regression when comments were left as is. Now `null` keywords are being convert correctly. (#620) (@fukusuket)
- `|contains|windash` modifier is now being converted to a usable form. (#622) (@fukusuket)

## v2.13.0-dev [2024/01/19]

- Comments in Sigma rules are left as is. Before, they would be stripped after conversion. (#568) (@fukusuket)
- Package management for the sigma conversion backend is now handled by [Poetry](https://python-poetry.org/) and static code analysis is performed by [Ruff](https://github.com/astral-sh/ruff). (#567) (@fukusuket)

## v2.12.0 [2023/12/19]

- Added field mapping support for registry rules (`service:`: `registry_add`, `registry_set`, `registry_event`) to detect built-in Windows event logs (`Security EID 4657`). Before, only Sysmon (`EID 12, 13, 14`) logs would be able to be detected. (#476) (@fukusuket)
- Added checks for ignoring rules that use field modifiers that Hayabusa does yet not support. (Ex: `|expand`) (#553, #554) (@fukusuket)

## v2.6.0 [2023/07/06]

- Added support for `category: antivirus`. (#456) (@fukusuket)

## v2.6.0 [2023/07/02]

There is now a field mapping check for `process_creation` rules.
There were about 60 `process_creation` rules that were being generated for `Security 4688` events, however, they were looking for fields that only exist in `Sysmon 1` so there was no need for them.
These incompatible `Security 4688` rules are no longer being created which will speed up processing time.
Also, `IntegrityLevel`, `User` and other fields are now being mapped to the correct field name and data type providing more accurate results.
This was all done thanks to Fukusuke Takahashi.

Details: https://github.com/Yamato-Security/hayabusa-rules/pull/445

## v2.5.1 [2023/05/14]

Rule converter was completely rewritten to only convert the `logsource` to `Channel` and `EventID` and leave everything else as the original sigma rule. (#396) (@fukusuket)
This makes reading the converted rules much easier as well as improves speed.

## v2.4.0 [2023/04/28]

Started to self host config files when converting rules from Sigma as the sigmac tool is deprecated and not updated anymore.

## v2.3.0 [2023/03/24]

`deprecated` and `unsupported` sigma rules are now also being added to the hayabusa-rules repository.

## v2.2.2 [2023/02/22]

Hayabusa now supports rules that use `base64offset|contains`.

## v1.8.1 [2022/12/14]

Fixed a bug when rules with fields with `null` values would not be converted properly.

## v1.8.1 [2022/12/06]

Stopped fixing regular expressions in `|re` fields during sigma rule conversion to work with the regex crate as we fixed the regular expressions upstream.

## v1.8.1 [2022/10/4]

Automatically update sigma rules daily.

## v1.4.2 [2022/07/20]

Include Channel in rule filename.

## v1.2.2 [2022/05/21]

Deprecated Japanese localization support: `title_jp`, `details_jp`, `description_jp`