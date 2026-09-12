# 資産ID秘匿 native 実行記録 — 2026-09-12

資産IDを乱数付きコミットメントにした経路を、softbank-l40s 上の5台の
AvalancheGoで実行した。確定ブロックの再実行結果と各ノードの台帳ルートを
毎回照合し、node3 の再起動後にも同じルートと復号残高を確認した。
判定は **smoke_only**。研究実装の機能実証であり、本番への昇格ではない。

## 観測した結果

証券2種・通貨2種を登録し、そのうち2資産を使用した。発行、予約、2回の
部分約定、残額の期限切れ返却、受領権の償還、受領した証券の再送金を実行した。
別の保有者の未約定予約についても、取消しと期限切れの両方を実行した。

| 保有者 | 証券残高 | 通貨残高 |
| --- | ---: | ---: |
| 当初の売り手 | 57 | 600 |
| 当初の買い手 | 53 | 410 |
| 未約定返却の確認用保有者 | 25 | 25 |

受取ウォレットは資産フィルターを送らずにノートをページ取得し、受領権の
暗号文もnative RPCから取得して復号した。ゼロ数量ノートの資産も識別できた。
最後のウォレット読取りはノード再起動後に行った。

資産のすり替えと数量証明の改変は、委員会署名を付け直した入力でも
証明検証で拒否された。受取暗号文の改変、旧エンドポイントへの持込み、
使用済みnullifierの再利用も拒否された。同一取引の再送は元の確定受領証を
返し、台帳を再更新しなかった。

公開台帳・取引・ノート取得結果を検査し、実資産IDは公開の資産定義と候補一覧
だけに現れた。このバイト検査は、暗号の安全性や周辺情報からの推測耐性の証明
ではない。同じ与信枠内の関連付けと、市場・発行者・時刻などの情報は残る。

実行時間は 137.9 秒（ネットワーク起動、期限待ち、再起動を含む）。
ビルドを含むランチャー全体は 162.9 秒。
最終台帳ルート: `5ce08e21335e450f33f0980154388b339dd895e532b1804245b2dd337a205122`。

## 証跡と版

- [実行結果](../research/asset-privacy/runs/native-04/outcome.json)
- [確定取引と各ノードのルート](../research/asset-privacy/runs/native-04/transitions.json)
- [拒否・再送時の観測](../research/asset-privacy/runs/native-04/rejections.json)
- [再起動後の読取り](../research/asset-privacy/runs/native-04/restart-readback.json)
- [公開情報の検査](../research/asset-privacy/runs/native-04/disclosure-check.json)
- [実行ログ](../research/asset-privacy/runs/native-04/native-client.log)
- [postflight](../research/asset-privacy/runs/native-04/postflight.json)

契約ID: `asset-privacy-native-five-validator-v1-unfilled-cohort4`  
契約SHA-256: `bdf78bf6e29597c73c5c805788b0ca133436cfeb2edf612858b292372f75a651`  
manifest SHA-256: `0ea55582838efb8986fdb0428b31d4e3d6a4b55a368894fa91d27c16cf178801`  
VMバイナリSHA-256: `5b91ca129e40f4055590682a3d558f593d5b4ba36bb5a8ed69fd51c8fb815e9a`

実際のplugin配置先のバイナリを読み直してハッシュ一致を確認した。
実行manifestに記録したソースも、作業ツリーと一致している。
Rust開発チェックは終了しており、そのログは
[development-checks.log](../research/asset-privacy/development-checks.log) に保存した。
開発チェックの結果は上記の実行・保存・復号の証拠と区別する。

## 実装範囲と残る接続

実装は `confidential_assets`、`confidential_notes`、native実行・状態保存、
ノート開封、受領権償還、およびRPC/SDK読取りにまたがる。詳細は
[仕様](CONFIDENTIAL_ASSETS.md) を参照する。

- 独立した機械で動くMPC証明生成と、実際のDeKYX承認サービスは未検証。
  この実証では委員会鍵と証明入力を1プロセスで構成した。
- QOMM/OCLOBの既存呼出しを新しい秘匿wrapperへ切り替える作業は別途必要。
  接続点は `rust/defmi/src/avalanche.rs` の既存application送信経路と、
  `rust/defmi/src/confidential_notes.rs` の私的予約検証入口。
  対応後は、実際のvenue入力から新しいnativeメソッドへ到達する経路を再実行する。
- 現行の楕円曲線方式が対象。PQC Onでは許可しない。匿名候補群は2〜64資産。
- 追加した暗号adapterは独立した暗号レビューを受けていない。
