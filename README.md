==================
wp-builder | 開発運用ガイド
==================

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
  [セキュリティ強化]
  node D:\dev-toolkit\wp-builder\bin\cli.mjs security --fix

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

6. 運用上の注意
------------------------------------------------------------
- 本ツールはプロジェクトルートを基準に動作します。
- 静的サイトで実行した場合、PHP関連のコマンド(セキュリティ)は安全にスキップされます。
- .envファイルはプロジェクトごとに作成せず、ツール実行拠点(D:\dev-toolkit)で管理してください。

============================================================