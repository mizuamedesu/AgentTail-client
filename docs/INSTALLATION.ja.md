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
標準の native モードは `/dev/net/tun` と `CAP_NET_ADMIN` を使います。
この権限がない環境では、次の userspace モードで VPN 内の TCP サービスへ接続できます。

## TUN のない環境（gVisor コンテナーなど）

dev.20 以降は gVisor netstack によるユーザー空間の VPN に対応します。
新規導入、または既存インストールの更新と切り替え:

```sh
curl -fsS https://agenttail.mizuame.app/install.sh | sh -s -- --vpn <VPN名> --userspace
```

導入済みの dev.20 以降で、承認済みの VPN を切り替える場合:

```sh
/usr/local/lib/agenttail/agenttail vpn up --name <VPN名> --userspace
```

Linux の既存シェルでは `. /etc/profile.d/agenttail.sh` でも PATH を反映できます。
macOS の絶対パスは `/Library/AgentTail/agenttail` です。
端末の秘密鍵と承認は再利用され、再承認は不要です。有効な承認をまだ持たない場合は承認画面が表示されます。
モードとポートは VPN ごとに保存され、サービス再起動後も維持します。
複数の VPN を使う場合は `--socks5 127.0.0.1:1081` など異なるポートを指定してください。

起動後は `vpn status --name <VPN名>` に `network_mode: userspace` と
`socks5: 127.0.0.1:1080` が表示されます。アプリケーションから SOCKS5 を指定して接続します。
`<VPN-IP>` は接続先端末の VPN 用 IPv4 アドレスです。

```sh
curl --socks5-hostname 127.0.0.1:1080 http://<VPN-IP>:8080/
ssh -o 'ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p' user@<VPN-IP>
```

SSH の例は SOCKS5 対応の OpenBSD netcat を使います。
SOCKS5 の TCP CONNECT のみ対応し、IPv4 リテラルを指定します。DNS 解決、UDP、ping、
OS 全体の透過ルーティング、この端末のホスト側サービスへの着信転送は提供しません。
待受は loopback のみに制限し、接続先も最新の ACL で許可された VPN ピアに限定します。
同じ端末のローカルプロセスはこのプロキシを利用できます。
WireGuard 暗号化、ICE/TURN、速度制限、承認期限を適用し、ACL の削除、down、失効時は既存の接続も閉じます。
停止は `agenttail vpn down --name <VPN名>`、native TUN へ戻す場合は
`agenttail vpn up --name <VPN名> --userspace=false` を使います。

## OS ごとの保管とビルド

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
