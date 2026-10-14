# インストールとビルド

公式配布は `https://agenttail.mizuame.app/install.sh` と `install.ps1` を使用します。
インストーラーは埋め込み公開鍵で manifest の署名と各ファイルのハッシュ・期限を検証します。
`--vpn <VPN ID>` で参加、`--no-service` でサービスなしの導入を選択できます。

Linux の amd64/arm64 は、`systemd-creds` が利用できるとき既存の systemd 暗号化保管を使用します。
修正版では、このコマンドのない新規環境も root 所有の `host.key` による AES-256-GCM 保管に対応します。
資格情報・host.key は `/var/lib/agenttail`（0700）の中で 0600 に保管します。
既存の systemd 形式は自動で置き換えません。これを読むには従来の systemd-creds と OS の鍵が必要です。
host 形式は systemd-creds の追加後も同じ鍵と形式を維持します。
root 権限やディスク全体へのアクセスを得た者は復号できるため、OS のアクセス制御が保護の前提です。

実行中の systemd がある Linux では systemd unit、それ以外の amd64/arm64 Linux では
プロセス監視・再起動を行うスーパーバイザーを使用します。
コンテナーの再作成・再起動後は、永続ボリュームにインストールと状態を保存し、
entrypoint から `agenttail service start` を実行してください。
VPN 通信には `/dev/net/tun` と `CAP_NET_ADMIN` が必要です。
この権限がない環境でも CLI の導入・承認はできますが、VPN 接続には実行環境の権限設定が必要です。

NanoKVM の riscv64 版は `/etc/agenttail` に host 形式で保存し、BusyBox init を使用します。
macOS は Keychain、Windows は machine DPAPI を使用します。

ビルド:

```sh
go build -trimpath -o build/agenttail ./cmd/agenttail
python3 scripts/render-installers.py
```

`agenttail licenses` で GPL 本文・公開ソースの URL・第三者の表示を確認できます。
公式リリースのタグと source archive は公開リポジトリの Releases で配布します。
archive には Go 依存ソースを `vendor/` として含め、`go build -mod=vendor` で利用できます。
上記の互換性修正を公式インストーラーで使用するには、修正版の署名済み CLI の公開が必要です。
