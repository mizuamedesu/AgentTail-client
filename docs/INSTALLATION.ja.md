# インストールとビルド

公式配布は `https://agenttail.mizuame.app/install.sh` と `install.ps1` を使用します。
インストーラーは HTTPS で取得した manifest の SHA-256、各ファイルのハッシュ・サイズ・期限を検証します。
`install.sh.sha256` と `install.ps1.sha256` も配布します。配布元の認証は HTTPS に依存します。
新規導入は `current`、Linux/riscv64 は専用の `current-nanokvm` チャネルを使用します。
配布 URL の `nanokvm` は従来のチャネル名で、対象アーキテクチャは RISC-V（Linux/riscv64）です。
従来の署名付き `stable` / `nanokvm` は保持し、既存の更新は署名検証を継続します。
公式インストーラーの再実行で新方式へ移行でき、既存の資格情報を保持します。
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

Linux/riscv64 版は `/etc/agenttail` に host 形式で保存し、常駐サービスには BusyBox init を使用します。
別の init を使う環境では `--no-service` で導入し、エージェントをフォアグラウンドで実行します。
macOS は Keychain、Windows は machine DPAPI を使用します。

ビルド:

```sh
go build -trimpath -o build/agenttail ./cmd/agenttail
python3 scripts/render-installers.py
```

`agenttail licenses` で GPL 本文・公開ソースの URL・第三者の表示を確認できます。
公式リリースのタグと source archive は公開リポジトリの Releases で配布します。
archive には Go 依存ソースを `vendor/` として含め、`go build -mod=vendor` で利用できます。
公開は全 native CI の成功後に行います。ハッシュ方式では署名秘密鍵は不要です。

インストーラーのハッシュ照合例:

```sh
curl -fsS https://agenttail.mizuame.app/install.sh -o install.sh
curl -fsS https://agenttail.mizuame.app/install.sh.sha256 -o install.sh.sha256
sha256sum -c install.sh.sha256
sh install.sh --vpn <VPN-ID>
```
