# 変更点

## v2.17.0 [2024/10/15]

- 相関ルールが正しく変換されないバグを修正した。 (#28) (@fukusuket)

## v2.17.0 [2024/09/22]

- `|fieldref`のモディファイア名は、Hayabusaの現在のバージョンで使用できるように、一時的に`|equalsfield`に変換される。(#24) (@fukusuket)

## v2.17.0 [2024/09/18]

- ビルトインのWMIイベント変換に対応した。 (#12) (@fukusuket)
  - これで、`wmi_event`のカテゴリーを持つSigmaルールは、以下のように変換される:
    - 次の条件が追加される。
    ```
    EventID: 5861
    Channel: Microsoft-Windows-WMI-Activity/Operational
    ```
    - `Destination`のフィールドは、`UserDataPossibleCause`に名前変更される。

## v2.17.0 [2024/09/16]

- バグ修正: Windowsのビルトインイベントログのルールに、誤って`sysmon`タグが追加されていた。(#21) (@fukusuket)

## v2.16.0 [2024/08/15]

- `depcrecated`および`unsupported`ルールについて、Sigma v1タグフォーマット(`_`)をv2フォーマット(`-`)に変換するようにした。(#18) (@fukusuket)

## v2.16.0 [2024/08/02]

- 設定ファイルを統合し、名前を変更した。 #11 (@fukusuket)
- 派生ルールIDを修正した。 #13 (@fukusuket)
- "Placeholder"ルールを無視するようにした。 #14 (@fukusuket)

## v2.16.0 [2024/07/30]

- 現在、Windowsビルトインの`Security 5156`イベントの`category: network_connection`ルールを作成している。 #10 (@fukusuket)

## v2.16.0 [2024/06/25]

- `.yml`ファイル内に複数のルールを持つSigma相関ルールの変換に対応した。 #9 (@fukusuket)
  
## v2.15.0 [2024/06/05]

- 無視リスト`ignore-uuid-list.txt`が追加され、Windows Defenderで過検知を引き起こすルールを無視するようにした。(#672) (@fukusuket)

## v2.15.0 [2024/06/04]

- windash修飾子(例: `|windash|contains`)は、Hayabusaのバージョン2.15.0からwindashをネイティブにサポートしたため、互換性のあるルールに変換せず、そのままにしている。 (#646) (@fukusuket)

## v2.13.0 [2024/03/27]

- `proven_rules.txt`を更新した。 (@YamatoSecurity)

## v2.13.0 [2024/03/24]

- 新しく作成されたルールには、新しいUUIDv4 IDが割り当てられる。(#629) (@fukusuket)
- `logsource_mapping.py`が、`near`条件でルールを作成していたバグを修正した。(#632) (@fukusuket)
- `logsource_mapping.py`のリファクタリングとユニットテストの追加。(#627) (@fukusuket)
- `exclude_rules.txt`の更新。(@fukusuket)

## v2.13.0 [2024/03/22]

- 変換後ルールに、新しいUUIDv4を割り当てるようにした。 (#629) (@fukusuket)
- コメントを残すように修正したときのリグレッションで、`null` が空文字に変換されていた。`null`を正しく変換するようにした。
- `|contains|windash` を利用可能な形式に変換するようにした。

## v2.13.0-dev [2024/01/19]

- Sigmaルールのコメントを残すようにした。以前は変換後に削除されていた。(#568) (@fukusuket)
- Sigma変換バックエンドのパッケージ管理は [Poetry](https://python-poetry.org/) 、静的コード分析は [Ruff](https://github.com/astral-sh/ruff) で実行するようにした。(#567) (@fukusuket)

## v2.12.0 [2023/12/19]

- ビルトインWindowsイベントログ (`Security EID 4657`) を検出するために、レジストリ ルール (`service:`: `registry_add`、`registry_set`、`registry_event`) のフィールドマッピングサポートを追加した。以前は、Sysmon (「EID 12、13、14」) ログのみが検出していた。 (#476) (@fukusuket)
- Hayabusa がまだサポートしていないフィールド修飾子を使用するルールを無視するためのチェックも追加した。 (例: `|expand`) (#553, #554) (@fukusuket)

## v2.6.0 [2023/07/06]

- `category: antivirus`に対応した。 (#456) (@fukusuket)

## v2.6.0 [2023/07/02]

`process_creation`ルールのフィールドマッピングがチェックされるようになった。
`Security 4688`イベント用に作成されていた`process_creation`ルールのうち60個が`Sysmon 1`にしか存在しないフィールドを探していたので、必要なかった。
これらの互換性のない`Security 4688`ルールは作成されなくなり、処理時間が短縮される。
また、`IntegrityLevel`、`User`などのフィールドが正しいフィールド名とデータ型にマッピングされるようになり、より正確な結果が得られるようになった。
貢献者: Fukusuke Takahashi

詳細: https://github.com/Yamato-Security/hayabusa-rules/pull/445

## v2.5.1 [2023/05/14]

ルールコンバータを完全に書き換え、`logsource`を`Channel`と`EventID`に変換するだけで、他は元のSigmaルールのままとした。 (#396) (@fukusuket)
これにより、変換されたルールを読むのが非常に楽になり、処理の速度も向上する。

## v2.4.0 [2023/04/28]

Sigmaからルールを変換する際、sigmacツールが非推奨で更新されなくなったため、設定ファイルを本レポジトリでホスティングするようにした。

## v2.3.0 [2023/03/24]

`deprecated`と`unsupported`のSigmaルールも、hayabusa-rulesリポジトリに追加されるようになった。

## v2.2.2 [2023/02/22]

`base64offset|contains`を使用するルールに対応した。

## v1.8.1 [2022/12/14]

`null`値を持つフィールドが入っているルールが正しく変換されない不具合を修正した。

## v1.8.1 [2022/12/06]

上流で正規表現を修正したため、regex crateで動作するようにSigmaルール変換時の`|re`フィールドの正規表現の修正を行わないようにした。

## v1.8.1 [2022/10/4]

Simgaルールを毎日自動で更新。

## v1.4.2 [2022/07/20]

ルールのファイル名にチャンネル名を記載する。

## v1.2.2 [2022/05/21]

日本語フィールドを廃止した: `title_jp`, `details_jp`, `description_jp`