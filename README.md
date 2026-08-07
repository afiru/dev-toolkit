wp-builder | 開発運用ガイド

1. 概要
------------------------------------------------------------
WordPressおよび静的サイト制作のワークフローを自動化するCLIツール。
Figma連携、画像最適化、セキュリティスキャン機能を提供します。

2. 初期設定
------------------------------------------------------------
1. D:\dev-toolkit にリポジトリを配置。
2. D:\dev-toolkit 直下に「.env」ファイルを作成。
3. 下記の内容を記述（※GitHub等へはアップロード厳禁）：
   FIGMA_TOKEN=あなたのアクセストークンをここに記述

3. 開発フロー (ターミナル2面運用)
------------------------------------------------------------
【ターミナル1：監視・自動生成】
  目的: ファイル保存時の自動include展開や画像最適化
  コマンド:
  npm install commander
  node D:\dev-toolkit\wp-builder\bin\cli.mjs watch

【ターミナル2：タスク実行】
  目的: Figma同期やセキュリティスキャン
  コマンド:
  [Security Fix Preview]
  node D:\dev-toolkit\wp-builder\bin\cli.mjs security:fix --file path\to\template.php

  PreviewでPlanとdiffを確認した後、対応環境でのみ明示的にapplyします。
  node D:\dev-toolkit\wp-builder\bin\cli.mjs security:fix --file path\to\template.php --apply

  [Figma同期]
  node D:\dev-toolkit\wp-builder\bin\cli.mjs figma:sync --file [FileKey] --page [NodeID]

4. ファイル構成と機能マップ
------------------------------------------------------------
以下の機能は各ファイルで実装されています。カスタマイズ時はここを確認してください。

■ コマンドエントリー
  ファイル: bin/cli.mjs
  役割: 実行コマンド(figma:sync, watch, security等)の定義と処理の振り分け。

■ Figma連携ロジック
  ファイル: lib/figma/generator.js
  役割: Figma APIから取得したJSONデータをSCSSクラス(cl_, bg_, rd_)へ変換する主要エンジン。

■ 整形・分類ロジック
  ファイル: lib/utils/formatter.js
  役割: 生成された_colorS.scssを「Text Colors」「Background Colors」「Border Radius」ごとに並び替えて整形。

■ 画像圧縮ロジック
  ファイル: lib/image/compressor.js
  役割: cwebp.exeを利用したWebP変換処理。

■ セキュリティスキャン
  ファイル: lib/security/scanner.js
  役割: PHPファイルの危険な関数を検出し、自動修復(Fix)するロジック。

■ ファイル操作ユーティリティ
  ファイル: lib/utils/fs-helper.js
  役割: ディレクトリ探索(walkFiles)など、システム内を横断する補助関数。

5. Figma同期の詳細手順
------------------------------------------------------------
1. ブラウザでFigmaを開く。
2. URLから以下を抽出：
   - FileKey: /design/ の直後のID
   - NodeID: node-id の「-」を「:」に変換したもの
3. 実行例:
   node D:\dev-toolkit\wp-builder\bin\cli.mjs figma:sync --file DNwqWZtEcaLHAaFGsJxxmi --page 4495:22765

6. Security Fix support matrix
------------------------------------------------------------

分類の意味:

- KEEP: productionで利用可能。
- KEEP_CANDIDATE: fail-closedの安全契約はあるが、正式KEEPに必要な検証または配布条件が残る。
- UNSUPPORTED: previewできる場合でもapplyや該当機能は利用不可。
- EXPERIMENTAL: 検証専用。productionでは利用しない。
- DISABLE_CANDIDATE: 互換性のため残っているが、新規利用は推奨しない。

### Platform / feature

| Platform | Feature | Status | Notes |
| --- | --- | --- | --- |
| Windows x64 | Security Analyzer | KEEP | Read-only analysis. |
| Windows x64 | `security:fix` Preview / Fix Plan | KEEP | Previewはファイルを変更しない。 |
| Windows x64 | PowerShell metadata inspection | KEEP | 権威あるWindows metadata判定。失敗時はfail-closed。 |
| Windows x64 | Native shadow inspection | KEEP_CANDIDATE | PowerShellとのshadow比較のみ。正式なEXE配布・署名は未完了。 |
| Windows x64 | Apply | UNSUPPORTED | `WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA`: strict metadata preservationを保証できないため。 |
| Windows ARM64 | Native inspection | UNSUPPORTED | 現在の正式candidateはx64のみ。 |
| Windows ARM64 | Apply | UNSUPPORTED | Windows applyはarchitectureにかかわらず未対応。 |
| Linux | Security Analyzer | KEEP | Read-only analysis. |
| Linux | `security:fix` Preview / Fix Plan | KEEP | Previewはファイルを変更しない。 |
| Linux | Metadata inspection | KEEP_CANDIDATE | `getfacl` / `getfattr`必須。検査不能時はfail-closed。 |
| Linux | Apply | KEEP_CANDIDATE | 条件付き。未対応metadata、filesystem、runtimeではblocking。 |
| Linux | Rollback | KEEP_CANDIDATE | same-directory hard-link recovery契約。追加の恒久Linux CI条件が残る。 |
| macOS / other POSIX | Security Analyzer / Preview / Fix Plan | KEEP | Read-only経路のみ。 |
| macOS / other POSIX | Apply | UNSUPPORTED | 専用metadata inspectorがないため。 |

Linux applyは正式KEEPではありません。ACL、xattr、security-sensitive metadata、hard link、
special mode、owner/group再現不能、inspector unavailable等を検出した場合は書き込まず停止します。

### PHP runtime

| PHP runtime | Status | Apply |
| --- | --- | --- |
| PHP 7.x | UNSUPPORTED | 不可。PHP 8.0以上が必要。 |
| PHP 8.0–8.1 | `LEGACY_COMPATIBILITY` | 不可。EOL compatibilityのみ。 |
| PHP 8.2–8.3 | verified candidate | 対応platformとmetadata条件を満たす場合のみ候補。 |
| PHP 8.4 | contract上のcandidate | 実runtime matrix未測定のためKEEP_CANDIDATE。 |
| PHP 8.5+ | `PHP_VERSION_UNVERIFIED` | 不可。Previewは可能。 |
| tokenizer unavailable | `PHP_TOKENIZER_UNAVAILABLE` | parse/apply不可。 |

### Windows native helper

Windows native helperはinspection-onlyのshadow inspectorです。PowerShell inspectorが引き続き
権威ある判定であり、native parity不一致時にnative結果へfallbackしません。現在の対象はx64、
`completeForReplace=false`で、production replace authorityはありません。

Phase BのReplaceFileW prototypeは **EXPERIMENTAL / NOT FOR PRODUCTION** です。継承DACLのstrict
preservationと、rollback recovery root-of-trustに既知の制約があるため、production applyへ接続しません。

### Legacy migration

旧`security --fix`は`DISABLE_CANDIDATE`です。現時点では互換性のためdisable/removeせず、挙動も変更しません。
新規利用ではFinding → Plan → Preview → Approval → Apply契約を持つ`security:fix --file <path>`へ移行してください。

7. 運用上の注意
------------------------------------------------------------
- 本ツールはプロジェクトルートを基準に動作します。
- 静的サイトで実行した場合、PHP関連のコマンド(セキュリティ)は安全にスキップされます。
- .envファイルはプロジェクトごとに作成せず、ツール実行拠点(D:\dev-toolkit)で管理してください。

============================================================
