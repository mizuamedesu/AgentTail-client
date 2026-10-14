# AgentTail native client

AgentTail が利用者に配布する CLI / VPN エージェントのソースを GPL-3.0-or-later で公開しています。
Linux・macOS・Windows・NanoKVM のバイナリー、インストーラー、署名付き更新・削除、OS 保管・サービス、
同梱スキル、ビルドと検証用スクリプトを含みます。

Web UI、ブラウザー用の暗号/共有パッケージ、Workers、D1、課金・運用処理は非公開リポジトリで管理します。
このリポジトリとソース archive に Web のコード・履歴は含めません。

```sh
go build -o build/agenttail ./cmd/agenttail
go test -race ./...
python3 scripts/render-installers.py
```

macOS の公開バイナリーはネイティブ macOS SDK と CGO が必要です。
公式配布は https://agenttail.mizuame.app 、API は https://agenttail-api.mizuame.app です。
第三者のライセンス表示は保持しています。LICENSE と LICENSES.md を参照してください。
署名秘密鍵はリポジトリに含みません。v0.1.0-dev.18 は従来の Go モジュール名を保った配布版のソースです。
