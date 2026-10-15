# AgentTail native client

AgentTail が利用者に配布する CLI / VPN エージェントのソースを GPL-3.0-or-later で公開しています。
Linux（amd64 / arm64 / riscv64）、macOS（amd64 / arm64）、Windows（amd64 / arm64）の
バイナリー、インストーラー、更新・削除、OS 保管・サービス、
同梱スキル、ビルドと検証用スクリプトを含みます。

RISC-V の配布対象は Linux/riscv64（64-bit、RV64GC）です。

gVisor など `/dev/net/tun` や `CAP_NET_ADMIN` を使えない環境では、
`agenttail vpn up --name <VPN名> --userspace` で gVisor netstack による
SOCKS5 TCP 接続を利用できます。既存の端末承認は保持します。
設定と使用例は [インストール手順](docs/INSTALLATION.ja.md#tun-のない環境gvisor-コンテナーなど) を参照してください。

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
新規導入は HTTPS と SHA-256 による配布物の検証を行います。既存の署名付き更新も継続してサポートします。
インストール手順とハッシュ照合は [INSTALLATION.ja.md](docs/INSTALLATION.ja.md) を参照してください。
