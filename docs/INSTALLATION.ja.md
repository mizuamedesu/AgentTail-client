# インストールとビルド

公式配布は `https://agenttail.mizuame.app/install.sh` と `install.ps1` を使用します。
インストーラーは HTTPS で取得した manifest の SHA-256、各ファイルのハッシュ・サイズ・期限を検証します。
`install.sh.sha256` と `install.ps1.sha256` も配布します。配布元の認証は HTTPS に依存します。
新規導入は `current`、Linux/riscv64 は専用の `current-nanokvm` チャネルを使用します。
配布 URL の `nanokvm` は従来のチャネル名で、対象アーキテクチャは RISC-V（Linux/riscv64）です。
従来の署名付き `stable` / `nanokvm` は保持し、既存の更新は署名検証を継続します。
公式インストーラーの再実行で新方式へ移行でき、既存の資格情報を保持します。
`--vpn <VPN ID>` で参加、`--no-service` でサービスなしの導入を選択できます。
CLI の JSON 出力は UTF-8 です。dev.21 以降は `<`・`>`・`&` をそのまま表示し、
SSH 利用例の `<identity_file>` などを読みやすく表示します。

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

## デスクトップ管理画面

dev.22 以降は、VPN 一覧と接続・切断ボタンを持つデスクトップ GUI を同梱します。
macOS Intel/ARM と Windows x64 は通常のインストーラーで導入します。
Linux x64 はデスクトップ環境（DISPLAY または WAYLAND_DISPLAY がある場合）で自動導入します。
Linux/Windows ARM64 と RISC-V は CLI を使用します。
GUI は OpenGL を利用できるデスクトップ環境が必要です。macOS の GPU を持たない仮想環境は対象外です。

macOS はアプリケーションの AgentTail、Windows はスタートメニューの AgentTail、
Linux はアプリケーションメニューの AgentTail を開きます。`agenttail gui` でも開けます。
既存の端末承認を使い、VPN を個別に選んで接続・切断します。
ウィンドウを閉じても常駐サービスと VPN の接続は維持されます。

dev.25 以降は、VPN を選んで `Remove VPN` からこの端末の参加を解除できます。
確認後にこの端末の接続を停止し、端末承認を取り消してローカルの登録と資格情報を削除します。
VPN 自体と他の端末は残ります。再参加には新しい承認が必要です。
サービスが停止中でも削除でき、サーバーの承認解除を確認できない場合は登録を残してエラーを表示します。

GUI を明示的に追加するには `install.sh --gui` または `agenttail gui install`、
省略するには `install.sh --no-gui` を使います。PowerShell は `-Gui` / `-NoGui` です。
導入済みの GUI は `agenttail update` で CLI とともに更新します。
`agenttail gui uninstall` は GUI のみを削除し、`agenttail uninstall --yes` はサービスとともに削除します。

GUI は通常ユーザーで実行し、起動時に OS の管理者承認を求めます。
補助プロセスは現在のウィンドウに対してのみ状態表示・VPN ごとの上げ下げと削除・サービス起動を提供します。
秘密鍵や端末資格情報は GUI へ渡しません。GUI のソースも配布するネイティブクライアントの範囲に含みます。
Web サイトやサーバーの実装は含みません。

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
更新やモード変更でプロセスが切り替わると、前の起動インスタンスの利用権が最大60秒残ります。
dev.21 以降の `join` / `up` は、この期限と再試行を含めて最大110秒待機します。
dev.20 が `CONFLICT` を返してもバックグラウンドの再試行は続くため、
`vpn status --name <VPN名>` が `up` なら再インストールや再承認は不要です。
複数の VPN を使う場合は `--socks5 127.0.0.1:1081` など異なるポートを指定してください。

起動後は `vpn status --name <VPN名>` に `network_mode: userspace` と
`socks5: 127.0.0.1:1080` が表示されます。アプリケーションから SOCKS5 を指定して接続します。
`<VPN-IP>` は接続先端末の VPN 用 IPv4 アドレスです。

```sh
curl --socks5-hostname 127.0.0.1:1080 http://<VPN-IP>:8080/
ssh -o 'ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p' user@<VPN-IP>
```

SSH の例は SOCKS5 対応の OpenBSD netcat を使います。
発信プロキシは SOCKS5 の TCP CONNECT に対応し、IPv4 リテラルを指定します。
SOCKS5 の DNS 解決・UDP ASSOCIATE と OS 全体の透過ルーティングは提供しません。
待受は loopback のみに制限し、接続先も最新の ACL で許可された VPN ピアに限定します。
同じ端末のローカルプロセスはこのプロキシを利用できます。
WireGuard 暗号化、ICE/TURN、速度制限、承認期限を適用し、ACL の削除、down、失効時は既存の接続も閉じます。
停止は `agenttail vpn down --name <VPN名>`、native TUN へ戻す場合は
`agenttail vpn up --name <VPN名> --userspace=false` を使います。

dev.24 以降は、認可された VPN ピアからこの端末の任意の TCP / UDP ポートへの受信を、
同じホストの `127.0.0.1:<同じポート>` へ転送します。ポートごとの追加設定は不要です。
SSH、HTTP、開発サーバーなどは loopback または `0.0.0.0` で待ち受けてください。
SSH サーバー自体の導入・起動は OS 側で行います。ホスト側サービスから見た接続元は loopback です。
UDP のメッセージ境界を保持し、通信のないセッションは30秒で閉じます。
ACL の削除、VPN の down、承認失効・lease 期限切れでは、ホストへの接続も閉じます。
AgentTail 自身の SOCKS ポートは、他 VPN への迂回接続を防ぐため受信転送の対象外です。
dev.25 以降は、新しい ICE 経路で送信鍵を更新し、受信鍵と既存の IP 接続を保ったまま再接続します。
旧クライアントが古いセッションの暗号化パケットを送る場合は、ハンドシェイクが観測されていないときだけ復帰用の probe を送ります。
通常の接続開始や ACL 復帰時のハンドシェイクに、先回りした probe が競合することを防ぎます。

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
### macOS のアプリ一覧

dev.23 以降は `/Applications/AgentTail.app` にアプリ本体を配置し、
インストールを実行したユーザーの Launch Services に登録します。
dev.22 のリンクだけの配置は、インストーラーの再実行時に自動修復します。
既存の端末承認は保持します。直接開く場合は `open /Applications/AgentTail.app` を使えます。
登録処理は [Apple の Launch Services の説明](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html#//apple_ref/doc/uid/TP30000999-CH202-CHDDGJFD) に従います。
