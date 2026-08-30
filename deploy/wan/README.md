# 7組織WAN配備

ここは、一台で7プロセスを動かす受入試験とは別の、7組織・7ノードWAN配備用である。

各組織は自分のホストで、相互TLS秘密鍵、暗号化された封印鍵、暗号化されたFROST状態、
自ノードのMP-SPDZ永続値、resident SQLite正本を保管する。調整役へ秘密鍵、FROST鍵断片、
MP-SPDZ永続値をコピーしない。秘密ファイルは0600、親ディレクトリは0700にする。
TLS秘密鍵、証明状態passphrase、inventory、DKG journalはシンボリックリンクにせず、
サービス実行ユーザーが所有する通常ファイルとして配置する。TLS秘密鍵とpassphraseは、
検査した同じファイル記述子から読み込まれ、他者読取権限・所有者不一致・過大サイズを拒否する。

手書きのJSONへ秘密鍵IDやZK-KYB証明を貼り付けてはいけない。
`prepare_wan_deployment`が、ノード秘密を中央へ集めずに設定を生成する。
[`deployment.example.json`](deployment.example.json)のDeFMI検査公開鍵、組織、ホスト、
保存先、承認済みMPCレジストリを実配備値へ置き換える。例のDeFMI鍵はRFCの試験鍵であり、
実DeFMIが署名に使うガバナンス固定済み公開鍵へ必ず置き換える。

`threshold: 2`はShamir多項式の次数であり、必要署名者数は3、すなわち3-of-7である。
この配備器はFROST鍵断片を生成しない。FROST鍵は全サービス起動後の分散DKGで各ノードに
直接作られる。MP-SPDZ秘密状態も配備器へ渡さない。各ノードの
`program_registry`は、そのノード上で別途承認・固定したMPC実行物を指す絶対パスであり、
存在しない場合や内容要約が変わった場合、residentサービスは起動を拒否する。

まずRust配備器をビルドする。

```bash
cargo build --manifest-path rust/Cargo.toml --release -p qomm-transport \
  --bin prepare_wan_deployment --bin serve_node --bin serve_proof_party \
  --bin discover_wan_inventory --bin provision_frost_cluster --bin wan_acceptance
```

オフライン認証局で、CA、調整役、起動用クライアント、署名済みZK-KYB名簿だけを作る。
ここではノード秘密鍵を作らない。

```bash
./rust/target/release/prepare_wan_deployment init-authority \
  --spec deploy/wan/deployment.json \
  --out /secure/qomm-authority
```

各組織は自分のホスト上で次を実行する。`private-out`はそのホストから出さず、認証局へ渡すのは
`request-out`のCSRと公開メタデータだけである。

```bash
./rust/target/release/prepare_wan_deployment init-node \
  --spec /etc/qomm/deployment.json --node N \
  --private-out /etc/qomm/node-N \
  --request-out /var/lib/qomm/enrolment/node-N
```

7組織から集めた公開要求を`requests/node-0`から`requests/node-6`へ配置し、
オフライン認証局で署名する。CSRの署名、ノード番号、組織、ホスト、共通名が仕様と一致しない
要求は拒否される。応答全体にもCA鍵で署名される。

```bash
./rust/target/release/prepare_wan_deployment sign-requests \
  --spec deploy/wan/deployment.json \
  --authority /secure/qomm-authority \
  --requests-root /secure/requests \
  --out /secure/responses
```

各組織は自分宛ての公開応答を受け取り、ノード上で適用する。ここで、証明書とローカル秘密鍵の
一致、CA署名、応答署名、全ファイル要約、クライアント証明書とZK-KYB証明の結び付き、
名簿署名を検査した後にだけ`node.json`と`proof-party.json`が作られる。

```bash
./rust/target/release/prepare_wan_deployment apply-response \
  --spec /etc/qomm/deployment.json --node N \
  --private-root /etc/qomm/node-N \
  --request /var/lib/qomm/enrolment/node-N \
  --response /media/verified-response/node-N
```

承認済みMPCレジストリと状態ディレクトリを配置した後、サービスを起動する。

```bash
sudo systemctl enable --now qomm-node@N qomm-proof-party@N
```

生成された`proof-party.json`は`complete_quote_proof: true`を必ず明示する。省略時は起動に失敗し、
旧来の要約確認だけへ暗黙に下がらない。proof側の`instance_id`はresident側とは別の長期鍵IDである。
証明ノードIDには完全証明モード、回路幅、しきい値、DeFMI検査鍵などの安全設定も入るため、
設定を変えるとIDも変わる。暗号化証明状態は形式V2で同じ設定要約を検査し、旧V1状態を
暗黙移行しない。実運用前のV1試験状態は、承認済み手順で新規DKG・inventory再固定を行う。

7サービスの起動後、まずFROST初期化用inventory候補を相互TLSの実応答から作る。
`--before-frost-dkg`ではFROST公開鍵を要求しないが、7組織、7ホスト、7つのresident・proof長期ID、
7つのOS設置ID、完全Quote証明、3-of-7設定はすべて必要である。同じOS上の別名や別ポートは
同じOS設置IDになるため拒否される。初回接続で観測した値はまだ受入証拠ではない。

```bash
./rust/target/release/discover_wan_inventory \
  --spec /etc/qomm/deployment.json \
  --coordinator-certificate /secure/coordinator/coordinator.cert.pem \
  --coordinator-private-key /secure/coordinator/coordinator.key.pem \
  --ca-certificate /secure/coordinator/ca.cert.pem \
  --before-frost-dkg \
  --out /etc/qomm/wan-dkg-inventory.json
```

候補のホスト、組織、証明書要約、長期ID、OS設置IDを別担当者が仕様・資産台帳と照合してから、
FROST DKGへ進む。inventoryは所有者だけが読める0600の通常ファイルでなければならない。

最初に一度だけ、7証明ノード間で3-of-7 FROST鍵を生成する。`--session`は配備ごとに
新しく生成した32バイト値を使い、再実行時も同じ値を使う。調整役は秘密鍵片を受け取らず、
署名済み公開情報と宛先別暗号文だけを中継する。各ノードは、確認済み参加者表、第1段階、
第2段階を順に暗号化保存する。同じ初期化IDなら各操作は何度実行しても同じ結果になるため、
全ノードが第2段階へ到達する前にノードまたは調整役が停止しても、同じコマンドで再開できる。
`--journal`は全第2段階応答が揃った時点で0600・原子的な名前変更・親ディレクトリ同期により保存し、
一部ノード確定後の再開にも残す。

```bash
./rust/target/release/provision_frost_cluster \
  --inventory /etc/qomm/wan-dkg-inventory.json \
  --session REPLACE_WITH_DEPLOYMENT_UNIQUE_64_HEX \
  --journal /var/lib/qomm/coordinator/frost-dkg-journal.json \
  --out artifacts/frost_provisioning.json
```

DKG後、同じ7サービスをもう一度発見する。今度は全ノードが同じFROST公開鍵要約を返さない限り
最終候補を生成しない。人手で値を転記しない。

```bash
./rust/target/release/discover_wan_inventory \
  --spec /etc/qomm/deployment.json \
  --coordinator-certificate /secure/coordinator/coordinator.cert.pem \
  --coordinator-private-key /secure/coordinator/coordinator.key.pem \
  --ca-certificate /secure/coordinator/ca.cert.pem \
  --out /etc/qomm/wan-inventory.candidate.json
```

DKG成果物の`public_package_sha256`と候補inventoryの
`expected_frost_public_package_sha256`が一致すること、7ノード情報が承認済み仕様と一致することを
別担当者が照合し、承認済みの`wan-inventory.json`として固定してからWAN受入を行う。
再起動コマンドはシェルを介さず、標準入力を閉じ、配列の各要素がそのまま実行され、
60秒で打ち切られる。

```bash
./rust/target/release/wan_acceptance \
  --inventory /etc/qomm/wan-inventory.json \
  --restart-node 3 \
  --out artifacts/seven_host_wan_acceptance.json
```

成果物が作られる条件は、7組織・7ホスト名・7 OS設置識別値、residentと証明サービスの
各7長期鍵ID、全相互TLS疎通、完全Quote証明モード、7ノードが共有するガバナンス固定済み
FROST公開鍵、実RTT測定、指定ノード上の両サービスの実再起動、両boot IDの変更、長期鍵IDと
証明状態世代の維持をすべて確認した場合だけである。ローカルホスト名、ループバック、
重複組織、重複長期鍵、同じOS上の別名は受入前に拒否される。

OS設置識別値はLinuxのmachine-idまたはmacOSのkern.uuidをdeployment IDで要約した値で、
単純なホスト別名を検出するためのものだが、TPMによる物理機器証明ではない。成果物も
`physical_hardware_attestation_verified: false`と記録する。物理7台を外部に証明する場合は、
別途TPM/TEE証明または独立監査済み資産台帳を受入条件へ追加する。
