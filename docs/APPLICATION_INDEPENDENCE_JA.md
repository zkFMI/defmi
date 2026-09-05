# DeFMIのアプリケーション独立性

更新日: 2026-09-05。この作業ツリーでは、基盤からAethelへの依存を除去した。Aethel向けの統合はAethelリポジトリが所有し、DeFMIはアプリ固有の型・状態decoder・専用RPCを持たない。

## 境界

| 基盤が持つもの | アプリが持つもの |
| --- | --- |
| ネイティブ資産・credit facility・予約・決済・replay index、ブロックとDB | アプリの業務状態・専用指図・資格や保証の対応付け |
| `ApplicationRuntime` trait | traitの決定的な実装と、それを組み込む専用バイナリ |
| opaqueな `application_states: BTreeMap<String, Vec<u8>>` | namespace、canonical encoding、意味と不変条件 |
| 共通の `defmivm.issueApplication` envelope | `application` / `method` / `params` の解釈と完全なstatementの承認 |
| 候補状態の作成、基盤検証、成功時の一括commit | アプリ状態の事前・事後検証と未知namespaceの拒否 |

`QommVm::default()` は `NoApplications` を使う。アプリ実行と、アプリ状態を含むDB・snapshotのロードを拒否する。`QommVm::with_application(Arc<dyn ApplicationRuntime>)` は、アプリ側のホストにだけ用いる。アプリを特定するfeatureやoptional dependencyは基盤へ追加していない。

汎用 `State::decode` が行うのは基盤側の構造検証である。VMがDB復元・起動・state syncで使用する際は、必ずそのホストの `validate_state` を呼ぶ。state syncは検証前に新状態をDBへ書かない。状態遷移は候補コピーで実行し、基盤・アプリ双方の検証成功後にのみ置き換える。

このinterfaceは、コンパイルして組み込む信頼されたconsensus code向けの公開Rust APIである。アプリ実装は基盤の状態型へアクセスでき、基盤と同じレビュー・決定性・承認の責任を持つ。sandboxや、ネットワークから任意コードを登録する仕組みではない。

## 所有場所の変更

DeFMIからAethel / DeCCPの専用reducerとテストを `aethel/crates/aethel-defmi-host` へ移した。`qomm-zkpi` の債権固有proof / wire / testは `aethel/crates/aethel-zkpi` へ移した。DeCCP・DeKYXのAethel adapterも、それぞれAethelが所有する。詳細と新ホストの起動方法は[Aethel側の説明](../../aethel/docs/FOUNDATION_INDEPENDENCE_JA.md)にまとめた。

汎用DeFMIのCargo依存に `aethel-core`、`deccp-aethel`、`deccp-core` は残らない。DeCCP coreの清算ロジック自体は独立したライブラリとして利用できる。

## 保存状態とRPCの互換性

アプリ状態がある場合は `application-state:v1` のdomain、長さ、決定的なmap encodingをrootへ含める。空mapは保存表現とrootへの追加を省略し、アプリを使わないネイティブDeFMIの既存空状態rootを保つ。

旧 `aethel` / `deccp` フィールドがあるsnapshotは `deny_unknown_fields` により拒否する。旧18個の専用RPC名は基盤のallowlistから除去した。新Aethelホストで共通envelopeへ包む場合も、アプリ状態のrootは旧形式と異なるため、旧署名やトランザクションをそのまま再利用しない。

既存アプリチェーンを移すには、旧checkpointを保存した上で明示的な移行と受入れが必要になる。今回、状態移行・チェーンリセット・デプロイは実行していない。

## 検証

`softbank-l40s:~/work/aethel-independence-20260905` の隔離された作業領域を使用した。DockerへはDeCCP・DeKYX・DeFMI・QOMM・zkPIの基盤ソースをmountし、OCLOBも依存検査用の読取snapshotとして追加した。`/work/aethel` が存在しないことを実コマンドで確認した。

6基盤workspaceの `cargo metadata --all-features` に対し、package名・source・manifest・dependencyにAethelが0件であることを機械検査した。Aethel側では12クレート、Clippyと57件のリリーステスト、専用バイナリの起動コマンドを別に検証した。

基盤の受入れコマンドは、DeCCP / DeKYXのworkspace全体、およびDeFMIの `qomm-defmi`・`qomm-avalanche-vm`・`zkpi-defmi-sdk`・`qomm-zkpi` と、QOMM / zkPI各コピーの `qomm-zkpi` に対するformat、Clippy、release testである。VMの境界テストでは、既定ホストの拒否、失敗時rollback、rootへの束縛・保存復元・replay拒否、旧状態と旧RPCの拒否を検査する。

検証ログはAethel作業ツリーの `.artifacts/foundation-isolation-*.log` に保存する。最初の試行は隔離コピーに `ZKPI_WIRE.md` を含め忘れたため、既存wireテストのcompileで停止した。仕様書を追加し、未完了の基盤検証を再開した。結果は同ディレクトリの検証receiptに集約する。

この検証は変更後のライブ7ノードMPC、独立運営、WAN、資産の全ライフサイクルを検証した記録ではない。


最終結果: format・全target Clippy・リリーステスト **526件**（基盤469件、Aethel57件）が通過。DeFMI既定バイナリとAethel専用バイナリのversion / VM IDも確認した。OCLOBはソースを変更せず依存metadataだけを検査した。ログと入力hashは[検証receipt](../../aethel/docs/verification/FOUNDATION_INDEPENDENCE_2026-09-05.json)に集約した。

2026-09-05の追加方針: この開発環境の旧Aethel状態は、ユーザー承認により移行対象とせず、存在する場合は削除して新規初期化する。これは他アプリの台帳や検証用fixtureを削除する指示ではない。
