# APIキー便 実装仕様書 v0.2 — PC版（macOS / Windows）

- 作成日: 2026-11-03（v0.1 を同日に検証して改訂）
- 対象: Claude Code による実装。リポジトリ直下に `docs/SPEC.md` として配置し、`CLAUDE.md` から参照する
- 規範語: **MUST**（必須）/ **SHOULD**（推奨）/ **MAY**（任意）
- 【要確認】: 実装開始時に該当crateのdocs.rs・公式ドキュメントで最新APIを確認し、結果を本書に追記する項目

## v0.2 の変更点（v0.1 を検証して直した所）

検証の方法は `verify/README.md`。**確かめた**は実物で動かした、または一次情報の原文を読んだもの。

| # | 変更 | 理由（確かめた事実） |
|---|---|---|
| 1 | 全解錠を最初に行う。Offer に署名を足し、Transport key と Peer 一覧を Vault に入れ、`peers.allow` と Keychain・DPAPI の別保管を廃止 | v0.1 は承認画面が Vault より先で、送信元の名前も指紋も出せず（§5.3）、§5.2 と §7.1 も食い違っていた。Transport key だけの者が承認画面を出せた。`ThisDeviceOnly` は単体 CLI で実現できない（Apple TN3137）。DPAPI は同じユーザーなら無確認で読める |
| 2 | `--exec` が実行に関わる変数を既定で拒否し、変数名を先に見せる（§8.3） | 侵害された送信端末が `NODE_OPTIONS` や `PATH` を混ぜると受信端末でコードが動く |
| 3 | ペアリングの確認を両画面で同じ値を比べる SAS に変更（§6.1） | v0.1 は両画面に「相手の指紋」を出すので、正しくても 2 つの値が別物で比べられなかった |
| 4 | `dotenvy` をやめ、展開なしの自前パーサに（§8.3） | 実測: `JWT_SECRET=$abc123` が空、`PW=pa$$word` が `pa`、`X=$HOME` が送信側のホーム。エラーに秘密を含む行が出る |
| 5 | label を Offer から暗号文の中へ移し、kind は署名済み Offer だけに置く（§7.1, §7.3） | 既定の TLS（ring）に ML-KEM が無く、Offer は耐量子でない（確かめた）。kind と label の二重持ちは不一致の検査漏れの元 |
| 6 | Ack に署名（§7.2） | 「届いた」を本物の受信者だけが言えるように |
| 7 | 外から来た文字列を制御文字・双方向制御の段階で拒否（§9.4） | 端末のエスケープ（OSC 52 など）で承認画面を偽装できる |
| 8 | ペアリングは Relay と DNS なしの端末でだけ行う（§4.1, §6） | iroh の user_data は全ての lookup に載り、公開 DNS に端末名が出る（ソースで確かめた）。pair ALPN も Relay 越しに届いていた |
| 9 | 既定の Relay を無効に（§4.1） | n0 公式: "We recommend against using public relays for sensitive or confidential data."、公開 Relay は "development and hobby use only" |
| 10 | CBOR は再エンコードして 1 バイトも違わないものだけ受ける（§7.1） | 試験が発見: 型のビット反転で text の鍵が bytes になり、serde が同じ名前と読むので、変えたフレームが署名検証を通った |
| 11 | `ed25519-dalek` と `x-wing` の `zeroize` を明示（§11） | `default-features = false` のままだと秘密が消えない。`x-wing` は既定の機能が空 |
| 12 | X25519 の非寄与を拒否（`DecapsulationKeyRejectNonContrib`） | 両端が自前なので受ける理由がない |
| 13 | §1.2 と §3 の主張を実態に合わせた | 「改ざん不能」「生体認証なしで復号不可」は言い過ぎだった（§3.2, §13） |
| 19 | バイナリのファイルも受ける。文字でないものは画面にも端末にも出さず、保存だけにする（§19.4） | オーナーの判断（第4回）。`.p12` や `.jks` を渡せるようにするため。悪用の恐れは上がる（§19.5） |
| 18 | `.env` などのテキストのファイルを渡せるようにした。名前は暗号文の中に入れる（§19.2, §19.4） | オーナーの判断。3 エンジンとも保存時に名前の先頭の点を外す（`.env` が `env` になる。実測）ので画面で伝える |
| 17 | 受け取る人は広告のあるページを通ってから中身を読む。鍵と ID はそのページに届かない（§19.1） | オーナーの判断ですべてのページに広告を置く。広告を置けない画面には広告のあるページを通って着く。悪意のあるスクリプトと Google の本物のスクリプトで、届かないことを実測した |
| 16 | サイト（広告あり）と `app.apikeybin.com`（第三者なし）に分け、ツールを枠に入れた（§19.1） | オーナーの判断でツールの画面に Google の広告を置く。最上位のスクリプトが枠の中を読めないことを実測した |
| 15 | ブラウザ版を §19 に追加。CLI の中身の検証とは別の脅威モデルとして分けた | オーナーの判断で両方を整備する（CLI だけだと受け取れない人が出る） |
| 14 | 事実の訂正: `x-wing` は rc でなく 0.1.1、`ed25519-dalek` は 3.0、Azure Artifact Signing は日本の組織は対象（個人は米国とカナダのみ）、iroh は 1.4.1 に固定（1.0.3 まで EID を SNI で送っていた） | 公式の文書と crates.io で確かめた |

---

## 1. 目的とスコープ

### 1.1 目的
APIキー・`.env` 等の機密情報を、自分の端末間（Mac ↔ Windows）で、**サーバに一切保存せずに**受け渡す。

### 1.2 設計目標：「どこを攻撃されても取れる情報がない」
| 攻撃面 | 侵害時に攻撃者が得るもの（目標） |
|---|---|
| 中継サーバ・DNS | 暗号文とメタデータ（接続の有無・時刻・IP・どの EID とどの EID か・パディング後サイズ）のみ |
| 通信経路（記録して後で解読） | 本文と label はなし（使い捨て鍵＋耐量子ハイブリッドKEM）。Offer の種類・サイズ区分・時刻は、既定の TLS が耐量子でないので将来読まれうる |
| 端末ストレージ（盗難・バックアップ） | 暗号文のみ（鍵も Peer 一覧も Vault の中。Vault は Protector なしで復号不可。受信物は既定で非保存）。Protector の限界は §3.2 |
| 配布・更新経路 | 改ざんを検出できるようにする（署名・公証・独立した再現ビルド・署名付きハッシュ）。検証しない利用者までは守れない |

### 1.3 スコープ（v0.x）
- CLI（`apikeybin`）。macOS（Apple silicon / T2）と Windows 10/11。Linuxはビルド・テストのみ（パスフレーズ保護）
- LANペアリング、LAN／インターネット越しの送受信
- 受信物の配送: `--exec`（環境変数として子プロセスに注入、既定推奨）/ `--out`（ファイル）/ `--print`（標準出力）

### 1.4 スコープ外（v0.x）
- モバイル（iOS/Android）、GUI（M7で Tauri 2）
- ブラウザ版は本書の主張の外。検証の結果は §19
- 1 MiB 超の転送、チーム共有・複数ユーザー、クラウドバックアップ、常時同期
- 受信端末が同一ユーザー権限以上のマルウェアに侵害されている場合の保護（§3.2）

---

## 2. 用語

| 用語 | 定義 |
|---|---|
| Device | `apikeybin init` 済みの端末 |
| Peer | ペアリング済みの相手Device |
| Endpoint ID (EID) | iroh のトランスポート公開鍵（Ed25519, 32B）。接続の宛先・認証に使う |
| Identity key (IK) | アプリ層の署名鍵（Ed25519）。Vault内に保管 |
| Vault | IK とPeer一覧を保持する暗号化ファイル |
| Protector | Vault の鍵（KEK）を生成・解錠する仕組み（Secure Enclave / Windows Hello / パスフレーズ） |
| Transfer | 1回の送受信（Offer → Accept → Data → Ack） |
| Relay | iroh の中継サーバ。暗号化パケットを転送するだけで中身は読めない |

---

## 3. 脅威モデル

### 3.1 攻撃者と対策
| 攻撃者 | 能力 | 得られるもの | 対策 |
|---|---|---|---|
| 中継・DNS運営者／侵害者 | 全パケットの観測・改ざん・遮断 | 接続メタデータ | QUIC(TLS 1.3)＋アプリ層E2E暗号、EIDとIKのピン留め、パディング |
| 経路の盗聴者（今録って後で解読） | 全通信の記録 | なし | 転送ごとの使い捨てX-Wing鍵（前方秘匿＋耐量子） |
| 端末ストレージの窃取者 | ファイル取得 | 暗号文のみ | 全ての鍵と Peer 一覧を Vault に入れ、HW鍵＋生体認証で暗号化。受信物は既定で非保存 |
| 侵害された Peer 端末 | 正しい鍵で悪意の中身を送る | `--exec` なら子プロセスの環境 | §8.3 の変数の拒否、変数名の事前表示 |
| 依存の乗っ取り | 悪意のある新版の公開 | 全て | 版の完全固定、`Cargo.lock` の検査。`cargo-deny` は新規の悪意を検出できない |
| 同一LANの能動攻撃者（ペアリング時） | なりすまし接続 | コード1回分の推測機会 | SPAKE2、コード使い切り、失敗で即中止 |
| ペア外の接続者 | 既知EIDへの接続 | 自端末IP（QUICハンドシェイク時） | 受け入れハンドラで許可リスト外を即切断 |
| 配布経路の改ざん者 | 偽バイナリ配布 | 全て | §13 の署名・公証・SHA256SUMS署名・Attestation |
| 通信妨害者 | 遮断 | DoSのみ | 対象外 |

### 3.2 ゼロにできないもの（READMEに明記 MUST）
1. 通信の有無・時刻・IPアドレス（中継・回線事業者から見える）
2. 通信妨害（DoS）
3. 同一ユーザー権限で動くマルウェア: 復号後の平文・子プロセスの環境変数・書き出したファイルを読める。Touch ID / Windows Hello のプロンプトを誘発し、ユーザーが承認すれば鍵を得られる
4. 送る中身の価値: 用途限定・短命なAPIキーの利用を推奨する
5. Protector の限界: Windows Hello は PIN でも通り、TPM の無い端末ではソフトウェア鍵になる。passphrase の Vault は弱いパスフレーズなら総当たりされる
6. Relay の運営者: 送信元と宛先の IP、時刻、量が見える（n0 公式）。固定の EID は網をまたいで追える
7. 依存クレートと配布経路の乗っ取り（§13 は検出を助けるだけ）

---

## 4. 全体構成

```
apikeybin (CLI)
 ├─ apikeybin-core      プロトコル型・CBOR・transcript・padding・暗号組立・Vault形式（I/Oなし）
 ├─ apikeybin-keystore  Protector（macOS SE / Windows Hello / passphrase）、Transport key保管
 └─ apikeybin-net       iroh Endpoint、ALPN: apikeybin/pair/1, apikeybin/xfer/1、mDNS
```

### 4.1 トランスポート
- iroh 1.4.1 に固定（QUIC）。まずホールパンチで直接接続、失敗時のみRelay経由
- Relayモード（`config.toml` の `relay`）:
  - `disabled`（既定）: LAN限定（`presets::Minimal` は暗号プロバイダの設定だけで、Relay も DNS も持たない。確かめた）
  - `n0`: n0社の公開Relay＋DNS address lookup（`presets::N0`）。n0 公式が機微なデータには勧めていないので、明示して選ぶ
  - `custom:<URL>`: 自前の `iroh-relay`（公開IP＋DNS名のサーバが必要。Cloudflare Workersでは不可）
- LAN発見: `iroh-mdns-address-lookup` 0.6.1（1.x では本体から分離）
  ```rust
  let endpoint = Endpoint::builder(presets::Minimal)
      .relay_mode(RelayMode::Disabled)
      .address_lookup(MdnsAddressLookup::builder())
      .secret_key(transport_sk)
      .alpns(vec![ALPN_PAIR.to_vec(), ALPN_XFER.to_vec()])
      .hooks(AllowPeers::from(&vault))
      .bind().await?;
  ```
  `secret_key`・`alpns`・`hooks`・`relay_mode` は `verify/iroh-probe` で実際に動かして確かめた
- DNS lookup に出るのは既定で Relay URL だけ（`PkarrPublisher` の既定が `AddrFilter::relay_only`。ソースで確かめた）
- `keylog` は使わない（既定で false。`SSLKEYLOGFILE` を設定しても書かないことを実測した）。0-RTT を使わない
- 常駐しない: 受信側は `apikeybin receive` 実行中だけ到達可能

### 4.2 接続受け入れポリシー（MUST）
- `EndpointHooks::after_handshake` で実装する。ここで `conn.remote_id()` と ALPN が分かり、拒否するとアプリに届かない（`verify/iroh-probe` で実測: 許可外の接続はアプリに見えず、送った中身も読まれない）
- ALPN `apikeybin/xfer/1`: 接続元EIDが解錠済みの Vault の Peer に無ければ切断
- ALPN `apikeybin/pair/1`: `apikeybin pair --show` 実行中の待受時間内のみ受け入れ、1接続で無効化
- それ以外のALPNは拒否（TLS の段階で失敗する。実測）

---

## 5. 暗号設計

### 5.1 プリミティブ
| 用途 | 方式 | crate |
|---|---|---|
| トランスポート | QUIC / TLS 1.3（EIDで相互認証） | `iroh` |
| 鍵共有 | X-Wing（X25519＋ML-KEM-768ハイブリッドKEM）。非寄与の X25519 を拒否 | `x-wing` 0.1.1（`DecapsulationKeyRejectNonContrib`） |
| AEAD | XChaCha20-Poly1305 | `chacha20poly1305` |
| KDF | HKDF-SHA256 | `hkdf`, `sha2` |
| ハッシュ | SHA-256（transcript） | `sha2` |
| 署名 | Ed25519（検証は `verify_strict`、弱い公開鍵を拒否） | `ed25519-dalek` 3.0 |
| PAKE | SPAKE2（Ed25519 group） | `spake2` |
| 鍵確認MAC | HMAC-SHA256 | `hmac` |
| パスフレーズKDF | Argon2id（m=64 MiB, t=3, p=1） | `argon2` |
| 乱数 | OS RNG | `getrandom` / `rand_core` |

- X-Wing サイズ: encapsulation key 1216 B / ciphertext 1120 B / shared secret 32 B
- `x-wing` crate は**独立監査を受けていない**（README明記）。draft-11 の試験ベクタとの一致を確かめた。`trait Kem` で抽象化し差し替え可能にする（候補: `libcrux-ml-kem`＋`x25519-dalek` でX-Wing combinerを実装、`aws-lc-rs`）。外部監査の範囲に必ず含める
- 上表の組み合わせ以外の暗号処理を書かない（MUST）

### 5.2 鍵の種類と保管
| 鍵 | 用途 | 保管 | 解錠 |
|---|---|---|---|
| Transport key（iroh SecretKey, Ed25519） | QUIC接続の識別（EID） | Vault | Protector（生体認証）。`send`・`receive` の最初に解錠する |
| Identity key（Ed25519） | Offer/Accept/Data/Ack の署名 | Vault | 同上 |
| Ephemeral X-Wing鍵 | 1転送の鍵共有 | メモリのみ | 転送ごとに生成・即破棄 |
| Vault KEK | Vault暗号化 | 保存しない（毎回導出） | Protector |

- ディスクに置く秘密は Vault だけにする。Keychain・DPAPI の別保管はしない
- 署名は Identity key だけが行い、Transport key は QUIC の接続にだけ使う

### 5.3 Vault

**パス**（`directories::ProjectDirs::data_local_dir()`）
- macOS: `~/Library/Application Support/apikeybin/`
- Windows: `%LOCALAPPDATA%\apikeybin\`（Roaming は使わない MUST。ドメイン環境で同期されるため）

**形式**
```
vault.bin := "SAV1" || u32_be(header_len) || header || aead_ct
header    := CBOR { v: 1, protector: ProtectorHeader, salt: [32], nonce: [24], created_at: u64 }
aead_ct   := XChaCha20-Poly1305(KEK, nonce, CBOR(VaultBody), ad = header)
VaultBody := { device_name: String, identity_sk: [32], transport_sk: [32], peers: [Peer], created_at: u64 }
Peer      := { name: String, endpoint_id: [32], identity_pk: [32], paired_at: u64 }
KEK       := HKDF-SHA256(ikm = protector_secret, salt = salt, info = "apikeybin/vault-kek/v1")
```
- 書き込み: 同一ディレクトリの一時ファイル → fsync → rename（原子的）。Unix は 0600、Windows は所有者のみのDACL
- 更新のたびに nonce を新規生成
- Vault喪失・Protector失効時: `apikeybin init --reset` → 再ペアリング。Vault に転送内容は入らないため失うデータはない

**指紋表示**: `SHA-256(identity_pk)` 先頭8バイトを16進4桁×4（例: `3F2A-9C1B-77E0-D4A5`）

### 5.4 Protector

```rust
pub trait Protector {
    fn kind(&self) -> ProtectorKind;
    /// 新しい protector_secret を生成し、復元に必要な header を返す
    fn create(&self) -> Result<(ProtectorHeader, SecretBox<Vec<u8>>)>;
    /// 生体認証等を経て protector_secret を復元する。reason はOSプロンプトに表示
    fn unlock(&self, hdr: &ProtectorHeader, reason: &str) -> Result<SecretBox<Vec<u8>>>;
}
```
`init` の既定は `auto`: macOS → Secure Enclave、Windows → Windows Hello、利用不可なら passphrase。passphrase に落ちるときは黙って進めず、理由を表示して確認を取る（MUST）。`doctor` は実際に使っている Protector を表示する。

#### (a) macOS: Secure Enclave
- Swift shim（`macos/SEShim`、CryptoKit）を `swift-rs` で静的リンク【要確認: ビルド設定】
- 鍵: `SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl:)`
  - access control: `SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])`
  - `.biometryAny` は使わない（パスワードで指を足すと通る）。指を変えると解錠できなくなるが、Vault に転送内容は無いので `init --reset` と再ペアリングで戻せる
  - オプション `--access userPresence`（Touch ID またはログインパスワード）
- create:
  1. SE鍵を生成し `dataRepresentation`（そのMacのSEでしか使えない不透明blob）を header に保存
  2. ソフトウェアの一時P-256鍵 e を生成し `ECDH(e, SE公開鍵)` → `protector_secret`
  3. e の公開鍵を header に保存し、e の秘密鍵を破棄
- unlock: blob からSE鍵を復元 → `sharedSecretFromKeyAgreement(with: e_pub)`（ここでTouch ID）
- 先行実装: `age-plugin-se`（CryptoKitでSE鍵をCLIから使用、access control選択あり）
- Apple silicon / T2 非搭載なら passphrase にフォールバック

#### (b) Windows: Windows Hello
- Windows Hello は暗号化APIを持たず署名のみ → Bitwarden と同方式: 固定challengeへの署名値から鍵材料を導出
- API: `Windows.Security.Credentials.KeyCredentialManager`（`windows` crate、WinRT）
- create:
  1. `RequestCreateAsync("apikeybin.vault.<random>", FailIfExists)`（TPM保護）
  2. `challenge = random[32]` を生成
  3. `RequestSignAsync(challenge)` → `sig` → `protector_secret = sig`
  4. header に `{ key_name, challenge, public_key }` を保存
- unlock: `OpenAsync(key_name)` → `RequestSignAsync(challenge)`（Helloプロンプト）→ 保存済み公開鍵で `sig` を検証 → `protector_secret`
- RSA PKCS#1 v1.5 署名は決定的で、同じchallengeから同じ値が出る → テストで確認（MUST。Microsoft の `OpenAsync` の説明は PSS と書いていて文書が割れている。PSS なら値が毎回変わり、この方式は成り立たない）
- `RequestSignAsync` に表示文言の引数は無い
- PIN でも通る。TPM の無い端末ではソフトウェア鍵になる（§3.2）
- 既知の限界（ドキュメントに明記 MUST）: 同一ユーザーの別プロセスも同じ鍵名で署名を要求でき、ユーザーがHelloを承認すれば同じ値を得る
- 禁止: 鍵材料を DPAPI や資格情報マネージャーに保存しない（Bitwarden の過去の脆弱性はDPAPI保管が原因）
- 【要確認】コンソールアプリからのHelloプロンプトの前面表示（ウィンドウハンドルを渡すinterop API）。Bitwarden はプロンプトが前面でないと生体認証が通らない旨をコードに残している

#### (c) Passphrase（Linux・フォールバック）
- `protector_secret = Argon2id(passphrase, salt, m=64MiB, t=3, p=1)`
- 入力は端末エコーなし。12文字未満は拒否

---

## 6. ペアリング（ALPN `apikeybin/pair/1`、v0.x は LAN 限定）

### 6.1 フロー
```
A: apikeybin pair --show                     B: apikeybin pair --join
 1. Vault解錠（本人確認）
 2. コード生成・表示  例: 482-語-語（語は EFF short wordlist）
 3. mDNS user-data に "sa-pair=1;name=<A>"
    （コード・そのハッシュは載せない）
 4. 120秒待受（pair ALPN有効）            5. mDNSで pair 中の端末を列挙・選択
                                          6. コード入力 → A へ接続
 7. SPAKE2:  A = start_a(pw, id_A=EID_A, id_B=EID_B) / B = start_b(同)
 8. 鍵確認: 各自 HMAC(K_c, "A"|"B" || th) を送り検証。不一致→中止・コード破棄
 9. K_e で暗号化して交換: { device_name, identity_pk, endpoint_id }
    受信した endpoint_id が実際の接続相手のEIDと一致しなければ中止
10. 両画面に同じ SAS を表示 → ユーザーが 2 つの画面を見比べる [y/N] → Vault に保存
    （B も手順 6 の前に Vault を解錠する）
```
- コード: 3桁数字＋EFF short wordlist（1,296語）×2 ≈ 30.6 bit。1コード1接続試行。失敗・タイムアウトで終了（MUST）
- `th = SHA-256("apikeybin/pair/1" || EID_A || EID_B || msg_A || msg_B)`
- `K_c = HKDF(K, th, "apikeybin/pair/confirm")`、`K_e = HKDF(K, th, "apikeybin/pair/enc")`、AEAD は XChaCha20-Poly1305。手順 9 の nonce は乱数 24B、AD は `"A"|"B" || th`
- `SAS = HKDF(K, th || EID_A || EID_B || identity_pk_A || identity_pk_B, "apikeybin/pair/sas")` の先頭 10 バイトを 16 進 5 桁×4 で表示。コードが漏れて LAN 内の攻撃者が両端と別々に SPAKE2 を通しても、th が違うので値が合わない
- ペアリング中の端末は `presets::Minimal`＋`RelayMode::Disabled`＋mDNS だけで動かす（MUST）。`user_data_for_address_lookup` は全ての lookup に載るので、N0 のままだと端末名が公開 DNS に出る
- mDNS の `name` は誰でも流せる未認証の文字列。§9.4 の検査を通し、「自称」として表示する

### 6.2 リモートペアリング
M5 で方式を決定（§17 #3）。

---

## 7. 転送プロトコル（ALPN `apikeybin/xfer/1`）

### 7.1 フレームとメッセージ
- QUIC 双方向ストリーム1本。フレーム = `u32_be(len) || CBOR`。`len` 上限 1,114,112 B（1 MiB + 64 KiB）を**decode前に**検査（MUST）
- 未知フィールド・型不一致・長さ超過は拒否
- decode した値を再エンコードして、受け取ったバイト列と 1 バイトも違わなければ受ける（MUST）。末尾のごみ・鍵の順番・重複・非最小の整数・不定長がこれで全て落ちる

```
OfferBody { v: 1, id: [16], kind: "env" | "text" | "file", bucket: u32, ts: u64 }
Offer  { body: bytes(CBOR の OfferBody), sig_o: [64] }
Accept { id: [16], ek: [1216], sig_r: [64] }
Reject { id: [16], reason: u8 }
Data   { id: [16], ct: [1120], nonce: [24], body: bytes, sig_s: [64] }
Ack    { id: [16], ok: bool, sig_a: [64] }
```

### 7.2 Transcript と鍵導出
transcript は**送受信した生バイト列**でハッシュする（再エンコードしない MUST）。

```
th0   = SHA256("apikeybin/xfer/1" || EID_sender || EID_receiver)
sig_o = Ed25519.sign(IK_s, "apikeybin/offer" || SHA256(th0 || OfferBody_bytes))
th1   = SHA256(th0 || Offer_bytes)
sig_r = Ed25519.sign(IK_r, "apikeybin/accept" || SHA256(th1 || id || ek))
th2   = SHA256(th1 || Accept_bytes)
(ct, ss) = XWing.Encaps(ek)
key   = HKDF-SHA256(ikm = ss, salt = th2, info = "apikeybin/xfer/payload/v1")   // 32 B
body  = XChaCha20-Poly1305(key, nonce = random[24], padded, ad = th2 || ct)
sig_s = Ed25519.sign(IK_s, "apikeybin/data" || SHA256(th2 || id || ct || nonce || body))
th3   = SHA256(th2 || Data_bytes)
sig_a = Ed25519.sign(IK_r, "apikeybin/ack" || SHA256(th3 || id || ok))
```

### 7.3 パディング
```
plaintext = CBOR { label?, content: bytes }   // kind は署名済みの Offer だけに置く
padded    = u32_be(len(plaintext)) || plaintext || 0x00 … （bucket 長まで）
buckets   = [1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB]
```
- 復号後、`padded` の長さが Offer の `bucket` と一致し、宣言した長さが収まり、詰め物が全て 0 であることを検証（MUST）

### 7.4 手順
**送信側**
1. `apikeybin send` → Vault解錠（生体）→ 宛先Peer解決 → EID指定で接続 → 署名した Offer
2. Accept受信 → Vault内の `identity_pk` で `sig_r` 検証 → Encaps → 暗号化 → Data
3. Ack受信 → `sig_a` 検証 → 終了

**受信側**
1. `apikeybin receive` → Vault解錠（生体）→ 待受（§4.2 で Peer 以外を切断）
2. Offer受信 → `sig_o` と時刻を検証。通らなければ何も表示せず切断
3. Vault の送信元名・指紋、種類、サイズ区分を表示 → `[y/N]`（入力は端末から。stdin のパイプでは受けない）
4. Yes → ephemeral X-Wing鍵生成 → Accept
5. Data受信 → `sig_s` 検証 → Decaps → 復号 → パディング検証・除去 → 配送（§8.3）
6. dk・key・平文バッファを zeroize → 署名した Ack

### 7.5 タイムアウトとエラー
- Offer→Accept: 120秒（ユーザー承認待ち）。その他の各ステップ: 30秒
- 署名不一致・未知Peer・サイズ超過・id不一致・期限切れ（`ts` が±5分外）→ 即切断
- 詳細なエラー理由はローカルにのみ表示し、相手には汎用の Reject コードのみ返す
- `id` は128bit乱数。転送ごとの ephemeral鍵により再送攻撃は成立しない

---

## 8. CLI 仕様

### 8.1 コマンド
```
apikeybin init    [--name NAME] [--protector auto|secure-enclave|windows-hello|passphrase] [--reset]
apikeybin id                                   # 自端末名・指紋・EID
apikeybin pair    --show | --join
apikeybin peers   list | rename OLD NEW | remove NAME
apikeybin send    <PATH|-> --to PEER [--kind env|text|file] [--label TEXT]
apikeybin receive [--from PEER] [--timeout SECS]
              (--exec [--allow-env NAME]... -- CMD [ARGS...] | --out PATH [--force] [--allow-synced] | --print)
apikeybin doctor                               # Protector可否・Vault状態・Relay・mDNS・同期フォルダ設定・ビルド情報
apikeybin config  get|set relay n0|custom:URL|disabled
```

### 8.2 終了コード
| コード | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 一般エラー |
| 2 | 引数エラー |
| 10 | 相手が拒否 |
| 11 | タイムアウト |
| 12 | 認証失敗（署名・PAKE・鍵確認） |
| 13 | 未知のPeer |
| 14 | Protector利用不可・キャンセル |
| （`--exec`） | 子プロセスの終了コードをそのまま返す |

### 8.3 振る舞い
- **send**
  - `kind` 自動判定: ファイル名 `.env*` → `env`（`envfile` で解析できなければ拒否。`--kind text` で上書き可）、`-`（stdin）→ `text`、その他 → `file`
  - `label` 既定: ファイルのbasename。暗号文の中に入り、受信者には復号後に見える
- **receive --exec**（既定推奨）
  - `kind=env` のみ受け付ける
  - 受け取った中身は `envfile` で読む。`$` は値であり展開しない。エラーは行番号だけを出す
  - `PATH`・`NODE_OPTIONS`・`LD_*`・`DYLD_*` など実行に関わる変数（`envfile::is_code_execution_vector`）は既定で拒否。通すには変数ごとに `--allow-env`（MUST）
  - 子プロセスを起動する前に、変数名（値は出さない）を表示する（MUST）
  - 現在の環境変数に上書きマージして子プロセスを起動。stdio は継承、Ctrl-C は子へ転送
  - 起動後、自プロセス内のコピーを zeroize。ディスクには書かない。std の `Command` は渡した値を消さないので、残りうることを README に書く
  - 注記: 子プロセスの環境変数は、OSによって同一ユーザーの他プロセスから読める
- **receive --out PATH**
  - 既存ファイルは `--force` なしで拒否。シンボリックリンクは辿らない
  - 同期フォルダ（§9.3）内は `--allow-synced` なしで拒否
  - 一時ファイル→rename の原子的書き込み。Unix 0600、Windows 所有者のみDACL
- **receive --print**: stdout に出力。stdout が TTY なら stderr に警告

### 8.4 使用例
```
# Windows 側（受け取って即実行。.env はディスクに残らない）
apikeybin receive --from mac --exec -- npm.cmd run dev   # Rust は .cmd を補わない

# Mac 側
apikeybin send .env --to win
```

---

### 8.5 ブラウザ版のリンクを扱う
```
apikeybin link <FILE|-> [--ttl 10m|1h|1d|7d] [--passphrase] [--no-name] [--server URL]
apikeybin open [LINK] [--out PATH [--force] [--allow-synced]] [--exec [--allow-env NAME]... -- CMD ARGS...]
```
- `link` はファイルの名前も一緒に暗号化して送る。`--no-name` で送らない。標準入力（`-`）に名前はない。送れない名前（§19.2）は読む前に止める
- **`open` は送り手が付けた名前を表示するだけで、書く先に使わない。** 書く先に使うと、送り手が `.zshenv` や `conftest.py` を置ける（一度作って、独立レビューの指摘で外した）。書く先は読む人が `--out` で決める。パスの区切りや制御文字を含む名前は、読み取りの時点で拒否する（§19.2）
- 端末に出すときは、送り手の文字のうち §9.4 の文字を `\u{..}` の形で見せる。そのまま流すと、エスケープ列でカーソルを動かし、行を隠し、OSC 52 でクリップボードを書き換えられるため。パイプとファイルにはバイトのまま渡す
- 合言葉は読み取りの前に聞く。まだ持っていない人が 1 回分を無駄にしない。`link --passphrase` は端末では 2 回聞く（打ち間違えると誰も読めないリンクになるため）
- `open` は配信サーバの JavaScript を信じずに読むための道。復号はこの端末で行う。形式は §19.2
- `LINK` を省くと隠れたプロンプトで受ける（シェルの履歴に残さない）。引数で渡すと警告する
- リダイレクトをたどらない（token が別の宛先へ渡るため）。https か、この端末の http だけ。応答は 64 KiB まで
- 読む前に確かめられることは先に確かめる（`--out` の先が既にある・フォルダである、同期フォルダ、書けないフォルダ、`--exec` のコマンドが見つからない）。1 回の読み取りを無駄にしない
- 読んだあとで届けられなかったとき（拒否した変数、`--exec` が読めない形、書けなかった）は、端末なら保存先を聞く。上書きはしない。パイプなら「リンクは使われた」と言って終わる
- 合言葉を間違えたら、サーバから消えた記録をメモリに持ったまま 3 回まで入れ直せる
- 終了コード: 20 使えないリンク、21 合言葉違い、22 拒否した変数、23 書けない場所
- 未実装: Windows の所有者のみの権限とコマンドの確認（M3）。`--exec` は複数行の値を読めない（保存はできる）。合言葉の NFC 正規化は Web 版だけが行う（新しい依存が要るため）。分解された形の文字を CLI に打つと一致しない

## 9. 端末側の安全要件（MUST）

### 9.1 メモリ・ログ
- 秘密値は `secrecy::SecretBox` / `zeroize::Zeroizing` で保持。`Debug`/`Display` で中身を出さない
- 秘密値をログ・エラーメッセージ・panic メッセージに含めない。`tracing` の既定レベルは WARN
- release プロファイル: `panic = "abort"`。Unix は起動時に `RLIMIT_CORE=0`。Windows はクラッシュダンプ（WER）を切る API を使う。ページファイルとハイバネーションの限界は README に書く
- `ed25519-dalek` と `x-wing` の `zeroize` 機能を必ず有効にする（§11）
- Vault平文・受信バッファは `mlock` を試みる（SHOULD、失敗しても続行）

### 9.2 機能の禁止
- CLI でクリップボードAPIを一切使わない（macOS のユニバーサルクリップボードで他のApple端末に渡るため）。ブラウザ版は §19.4
- テレメトリ・クラッシュレポーター・自動更新を入れない（v0.x）

### 9.3 同期フォルダ検出（`--out` 用、ヒューリスティック）
- macOS: `~/Library/Mobile Documents/`（iCloud Drive）、`~/Library/CloudStorage/`（OneDrive・Google Drive・Dropbox 等）、iCloud「デスクトップと書類」有効時の `~/Desktop`・`~/Documents`【要確認: 有効判定方法】
- Windows: 環境変数 `OneDrive` / `OneDriveConsumer` / `OneDriveCommercial` 配下。`SHGetKnownFolderPath` で解決した Desktop・Documents が OneDrive 配下なら同期対象（既知フォルダの移動）
- パスを正規化してから判定する。判定できないときは通さない
- Dropbox・Google Drive など Windows の他社の既定の置き場も見る
- 検出時は理由を表示して拒否

### 9.4 承認画面と外から来た文字列
- Offer 承認時に、送信元のPeer名と指紋（短縮形）を必ず表示する（なりすまし承認の防止）。Peer名と指紋は解錠済みの Vault から読み、相手の申告を使わない
- label・device_name・ファイル名は、制御文字、見えない文字（Unicode 18.0 の Default_Ignorable_Code_Point: 双方向制御、ゼロ幅、異体字セレクタ、タグ文字など）、行と段落の区切り、長さ超過を受信の段階で拒否する（`text::is_forbidden`）。エスケープで画面を偽装させない。本文は拒否できない（送り手の秘密そのもの）ので、端末に出すときに同じ文字を見える形にする（§8.5）

---

## 10. リポジトリ構成

```
apikeybin/
├─ Cargo.toml                 # workspace
├─ rust-toolchain.toml
├─ deny.toml
├─ CLAUDE.md                  # §15 を転記
├─ SECURITY.md
├─ crates/
│  ├─ apikeybin-core/          # messages, transcript, padding, kem trait, aead組立, vault形式, envfile, text
│  ├─ apikeybin-keystore/      # Protector trait, macos.rs, windows.rs, passphrase.rs
│  ├─ apikeybin-net/           # endpoint, accept_policy, pair, xfer（状態機械）
│  └─ apikeybin-cli/           # clap, prompts, deliver(exec/out/print), sync_folder, doctor
├─ macos/SEShim/              # Swift Package（CryptoKit）
├─ verify/                    # 検証（web-threat, iroh-probe, mutation, kat, proverif）
├─ fuzz/                      # cargo-fuzz targets
├─ docs/
│  ├─ SPEC.md                 # 本書
│  ├─ PROTOCOL.md             # §6–7 を独立文書化（監査用）
│  └─ THREAT_MODEL.md         # §3 を独立文書化
└─ .github/workflows/         # ci.yml, release.yml
```

---

## 11. 依存crate（初期案。バージョンは実装開始時に固定）

| crate | 用途 | 備考 |
|---|---|---|
| `iroh` =1.4.1 | トランスポート | 1.0.3 までは EID を SNI で送っていたので、それより後に固定 |
| `iroh-mdns-address-lookup` =0.6.1 | LAN発見 | 1.x では別crate |
| `x-wing` =0.1.1 | KEM | 未監査。`trait Kem` 越しに使用。`zeroize` と `getrandom` を有効に |
| `ed25519-dalek` =3.0.0 | 署名 | `verify_strict`。`zeroize` を有効に |
| `chacha20poly1305` | AEAD | `XChaCha20Poly1305` |
| `hkdf`, `sha2`, `hmac` | KDF・ハッシュ・MAC | |
| `spake2` | PAKE | 監査範囲に含める |
| `argon2` | パスフレーズKDF | |
| `zeroize`, `secrecy` | メモリ消去 | |
| `ciborium` + `serde` | CBOR | |
| `clap` 4 | CLI | |
| `tokio` | async | |
| `directories` | 保存先パス | |
| `tracing` | ログ | |
| `windows` | WinRT（KeyCredentialManager）・Win32（DACL・KnownFolder） | Windows のみ |
| `swift-rs` | Swift shim 連携 | macOS のみ【要確認】 |
| `aes-gcm` =0.11.1 | ブラウザ版の形式（AES-256-GCM） | 2026-11-03 承認。NCC Group の監査あり（README） |
| `pbkdf2` =0.13.0 | 合言葉 | 2026-11-03 承認 |
| `ureq` =3.5.1 | HTTPS | 2026-11-03 承認。CLI のみ |
| `rpassword` =7.5.4 | 隠れた入力 | 2026-11-03 承認。CLI のみ |
| dev: `proptest`, `libfuzzer-sys` | テスト | |

方針（MUST）
- 新規依存の追加は人間の承認が必要
- `default-features = false` を基本とし、機能は 1 つずつ名指しする。`zeroize` を落とさない
- 版は `=` で完全に固定する
- `cargo-deny` でライセンス・既知脆弱性・重複・取得元を検査

---

## 12. テスト

| 種別 | 内容 |
|---|---|
| 単体 | transcript の固定ベクタ（KAT）、パディング境界、CBOR decode の拒否（未知フィールド・長さ超過） |
| 異常系 | body / ct / nonce / sig の改ざん、別Peerの署名、未知EID、期限切れ、bucket不一致、Accept前のData、二重Offer |
| 性質 | `proptest`: pad/unpad の往復、任意バイト列の decode が panic しない |
| ファズ | CBORメッセージ decode、Vault header 解析、envfile 解析 |
| 変異 | `verify/mutation/mutate.py`: 安全の検査を 1 つずつ消して試験が落ちることを確かめる。残れば試験の穴。検査を足したらここにも足す（MUST） |
| 結合 | 同一プロセスに2 endpoint（Relay無効・localhost）で pair → send → receive（print / out / exec） |
| 実機 | Touch ID / Windows Hello（`#[ignore]`＋手順書） |
| CI | macOS（arm64）・Windows・Ubuntu で fmt / clippy `-D warnings` / test / cargo-deny / fuzz短時間 / gitleaks |

---

## 13. ビルドとリリース

### 13.1 再現可能ビルド
- `cargo build --locked`、`SOURCE_DATE_EPOCH` 固定、`--remap-path-prefix`、`codegen-units = 1`、`lto = true`、`strip = true`
- 同じランナーで 2 回作って一致を見るだけでは改変を検出できない。別の環境で別の人が作った物と比べて初めて意味がある（配布物そのものの Mac は署名に時刻が入るので、署名前の物で比べる）

### 13.2 プラットフォーム別
- **macOS**: arm64＋x86_64（または `lipo` で universal2）。Developer ID 署名（hardened runtime）→ `notarytool` で公証。単体バイナリはステープル不可のため、配布形式は pkg も検討
- **Windows**
  - v0.x: 署名なし zip（自分用。SmartScreen 警告あり）
  - 配布段階: MSIX＋Microsoft Store（登録無料、Microsoft が署名、App Execution Alias で `apikeybin` コマンド化）または OV コード署名証明書
  - Azure Artifact Signing は日本の組織は対象、個人は米国とカナダのみ（Microsoft の quickstart で確かめた）

### 13.3 成果物の検証手段
- `SHA256SUMS` を YubiKey 上の `ed25519-sk` 鍵で署名: `ssh-keygen -Y sign -f <sk鍵> -n file SHA256SUMS`
- GitHub Artifact Attestations（`actions/attest-build-provenance`）
- 検証の手順と鍵の入手先を README に書く。鍵はリリースと別の経路にも置く（リリースと README を書き換えられる者が、バイナリと鍵を一緒に差し替えられるため）。古い版への差し戻しは版番号で検出できるようにする

### 13.4 CI/CD の保護
- 全 action をコミットSHAで固定
- `permissions:` は最小限
- `pull_request_target` を使わない
- release は保護環境＋手動承認

---

## 14. マイルストーンと受け入れ基準

| # | 内容 | 受け入れ基準 |
|---|---|---|
| M0 | workspace・CI・cargo-deny・CLAUDE.md・rust-toolchain | CI が3 OSで緑 |
| M1 | core: メッセージ・transcript・パディング・X-Wing/AEAD組立・Vault形式（passphrase） | KAT・異常系・proptest 全通過。`init` / `id` が動作 |
| M2 | net（LAN）: endpoint・許可リスト・LANペアリング・転送・`receive --print/--out` | 同一LANの Mac↔Windows で pair→send→receive 成功。未ペア端末の接続を即切断。改ざんテスト通過 |
| M3 | Protector: macOS SE（Swift shim）・Windows Hello | 解錠時に生体プロンプト。キャンセルで終了コード14。vault.bin を別PCにコピーしても復号不可 |
| M4 | 配送と接続: `--exec`・同期フォルダ検出・`doctor`・Relay設定・インターネット越し | 別ネットワーク間で送受信成功。`--exec` で子にenv注入。同期フォルダへの `--out` を拒否 |
| M5 | リモートペアリング | §17 #3 の決定に従う |
| M6 | リリース・OSS公開 | §13 と §16 のチェックリスト完了 |
| M7 | Tauri 2 GUI（トレイ常駐・受信承認ダイアログ）→ iOS / Android | 別仕様書 |

---

## 15. Claude Code 向け実装ルール（CLAUDE.md に転記）

1. 暗号プリミティブを自作しない。§5 の組み合わせ以外を書かない。変更する場合は先に本書を更新する
2. 新しい依存を追加しない（`verify/` の中の試験用の crate は製品に入らないので別）。必要な場合は理由・代替案・ライセンスを提示して作業を止め、承認を待つ。存在を確認できない crate 名を使わない
3. 秘密値は `SecretBox` / `Zeroizing` で保持し、`Debug` / `Display` / ログ / エラー / panic に出さない
4. `unsafe` は keystore の FFI 境界のみ。各 `unsafe` に `// SAFETY:` コメントを付ける
5. `unwrap` / `expect` を本番コードで使わない（テストは可）
6. 受信データは長さ上限を検査してから decode する
7. PRには正常系と改ざん系のテストを必ず含める
8. CLI でクリップボードAPIを使わない（ブラウザ版は §19.4）
9. 【要確認】項目は実装前に docs.rs・公式ドキュメントで確認し、結果を本書に追記する

---

## 16. OSS 公開チェックリスト（M6）

- [ ] git 履歴全体を gitleaks / trufflehog で走査（開発中の `.env`・APIキー）。検出時は履歴を作り直す
- [ ] GitHub secret scanning のプッシュ保護、非公開脆弱性報告を有効化
- [ ] main ブランチ保護: レビュー必須・署名コミット必須・CODEOWNERS（`crates/apikeybin-core`・`crates/apikeybin-keystore` はオーナー承認必須）
- [ ] LICENSE（§17 #2）、SECURITY.md、PROTOCOL.md、THREAT_MODEL.md、再現ビルド手順
- [ ] README に限界を明記: §3.2、Windows Hello の性質、`x-wing` 未監査、モバイル未対応

---

## 17. 未決事項

| # | 項目 | 選択肢 | 決定時期 |
|---|---|---|---|
| 1 | 名称 | APIキー便に決定（2026-11-06）。CLI と crate は `apikeybin` | 済 |
| 2 | ライセンス | MIT OR Apache-2.0 に決定（2026-11-05）。※ `magic-wormhole` crate（EUPL-1.2）を使う場合は整合を確認 | 済 |
| 9 | ソースの置き場 | GitHub の組織 `apikeybin` に決定（2026-11-06）。`https://github.com/apikeybin/apikeybin` | 済 |
| 10 | HSTS の preload 一覧 | 公開して `check_live.py` が通ったら hstspreload.org に申請する（2026-11-06）。`.com` は最初から一覧に入っていないため | 公開の後 |
| 3 | リモートペアリング | magic-wormhole の mailbox（公開 or 自前）／ 自前ランデブー（公開する nameplate と PAKE 用の秘密を分離）／ 当面 LAN 限定 | M5 |
| 8 | ブラウザ版の扱い | §19 | M1 の後 |
| 4 | Relay | なし（既定）／ n0 公開／ n0 の有料／ 自前 `iroh-relay`（VPS）。自前は他人の通信の媒介に当たりうる | M4 |
| 5 | Windows 既定 Protector | Windows Hello 単独 ／ Hello＋パスフレーズ併用 | M3 |
| 6 | KEM 実装 | `x-wing` ／ `libcrux-ml-kem`＋`x25519-dalek` で combiner 実装 ／ `aws-lc-rs` | M1（trait で後から差し替え可） |
| 7 | 解錠の頻度 | `send`・`receive` の開始ごとに生体認証（既定）／ 一定時間キャッシュ | M3 |

---

## 18. 参考（実装時の確認先）

- iroh: https://docs.rs/iroh ／ https://docs.iroh.computer
- iroh mDNS: https://docs.iroh.computer/connecting/local-address-lookup
- x-wing: https://docs.rs/x-wing ／ draft-connolly-cfrg-xwing-kem
- spake2: https://docs.rs/spake2
- age-plugin-se（CryptoKit Secure Enclave の先行実装）: https://github.com/remko/age-plugin-se
- Windows Hello の鍵導出（Bitwarden 実装と既知の限界）: https://community.bitwarden.com/t/windows-credentials-manager-has-bitwardens-credentials-in-it-what-why-is-this-a-security-issue/85928/31
- DPAPI 保管の脆弱性事例: https://blog.redteam-pentesting.de/2024/bitwarden-heist/
- magic-wormhole.rs: https://github.com/magic-wormhole/magic-wormhole.rs

---

## 19. ブラウザ版（Web）

CLI を入れられない人（受け取る相手がターミナルを使わない場合など）のために、ブラウザだけで渡せる形を用意する。§1.2 の主張は CLI についてのもの。ブラウザ版はページのコードをサーバが配るので、同じことは言えない（§19.5）。実装は `web/`。

### 19.1 配置（MUST）
- `app.apikeybin.com`（`web/`）: ツール本体、API、受け取る画面。第三者のコードを一切載せない。`worker/` と `public/` に実行時の依存はない
- `apikeybin.com`（`site/`）: 説明、読み物、Google の広告。秘密を受け取る部品を置かない。サーバのコードも持たない。ツールは `app.apikeybin.com/embed` を枠で読み込む
- `/embed` だけが `frame-ancestors https://apikeybin.com`。ほかは `'none'`。枠を使わず直接開く `app.apikeybin.com/` が「広告のない画面」。ここへのリンクは「守れないもの」の中だけに置き、ツールのそばには置かない。受け取る画面のリンクも `https://apikeybin.com/` へ向ける。`noindex` にして、検索からは `apikeybin.com` に着くようにする
- **広告スクリプトは最上位で動かす必要がある。** AdSense は広告を枠に入れるのを禁じている。だからツールのほうを枠に入れる。別オリジンなので、最上位のスクリプトは枠の中を読めない（§19.6 で実測）
- **受け取る画面（`/s/<id>` と `/open`）に広告スクリプトを置かない。** 置くとリンクの鍵が広告の通信に載る（実測）。AdSense の「人と人の私的な通信の画面」の禁止にも当たると読む。スクリプトのない画像とリンクだけなら置ける
- **受け取る人は、中身を読む前に広告のあるページ（`apikeybin.com/open`、`site/public/open.html`）を通る。**
  1. `app.apikeybin.com/s/<id>#1.<secret>` を開くと、`app.apikeybin.com` の `sessionStorage` に ID と `#` の後ろを置く
  2. `history.replaceState` でアドレスから消してから、`location.replace` で広告のあるページ（`https://apikeybin.com/open#go`）へ移る。`#go` は毎回同じ印で、鍵でも ID でもない。**URL にも Referer にも ID と鍵を載せない**
  3. そのページのボタン（`https://app.apikeybin.com/open`）で戻り、`sessionStorage` から取り出す。鍵は読む直前に消す。置いてから 1 時間で無効
- `sessionStorage` はオリジンごと・タブごと。広告のあるページのスクリプトからは読めない（§19.6 で実測）。使えない環境では広告のあるページを通らずに読む。移動するのは本番のオリジンのときだけで、手元の試験では通らない
- 広告のあるページは読み物にする。AdSense は移動のための画面（"navigation"）と中身の薄い画面を禁じているので、受け取ったキーの扱い方を書く。スクリプト・タイマー・自動の移動を置かない（試験で確かめる）
- **このページに Google の広告を置かない。** 広告はスクリプトのない画像とリンクだけにする。Google の "Please don't place content ads on interstitial pages" と "Placed on pages published specifically for the purpose of showing ads." に当たる恐れがあり、アカウントが止まると作り直せないため
- このページのボタンと案内は、`#go` で来た人にだけ見せる（CSS の `:target`。スクリプトなし）。リンクを開かずに来た人には読み物だけを見せ、行き先のないボタンを出さない（AdSense: "Linking to content that doesn't exist"）
- `apikeybin.com` のフッターから、ソース（`https://github.com/apikeybin/apikeybin`）へ「GitHub」の文字でリンクする（試験で確かめる）。比較記事に書いたライセンスを、読む人が確かめられるように。リンクの途中で折り返さない
- `apikeybin.com` の各ページ（404 を除く 12 枚）に、共有したときのカードの印を置く。`og:type`（記事は article、ほかは website）、`og:site_name`、`og:locale`、`og:title`・`og:description`・`og:url`（ページの title・description・canonical と同じ）、`og:image`（`https://apikeybin.com/og.png`、1200×630）とその大きさと説明、`twitter:card`（summary_large_image）。画像の文は、ページに書いてある事実だけにする（試験で確かめる）
- `apikeybin.com` にプライバシーポリシー、利用規約、通報のページを置く。プライバシーポリシーには Google が求める内容（第三者配信事業者の Cookie、広告設定へのリンク）を書く（試験で確かめる）。運営者の名前や住所は書かない
- 広告の枠は、広告が出せるようになるまで見せない（`<html class="no-ads">`。空の枠と「広告の枠」の文字が公開の画面に出ないことを試験で確かめる）。広告を入れるときに、作る画面と読み物のページからこの印を外す
- `apikeybin.com` の 404 には広告を置かない（AdSense: "dead end" の画面の禁止）。受け取る画面の「使えません」も同じ
- 作る画面の広告は、上に小さい枠（スマホ 320×100、PC 728×90）、PC の右に縦長（300×600）、スマホはツールの下、ページの途中に 1 つ。下に固定する広告は置かない（測るとツールのボタンに重なった）
- 広告はボタンから 150px 以上離す（Google が出している数字は "moving ad units 150 pixels away from your content" だけ。試験で測る）。広告の割合は Better Ads の基準（PC 50%、スマホ 30%）を超えない（試験で測る）
- AdSense の自動広告（Auto ads）は読み物のページだけで使う。作る画面と受け取る人が通るページでは使わない。ツールの上に重なる形式を場所で除けないため
- 秘密のページでは Cookie を使わない（`.apikeybin.com` の広告の Cookie が届いても読まない）
- 配置の根拠は §19.6 の測定

### 19.2 暗号
| 用途 | 方式 | 実装 |
|---|---|---|
| 暗号化 | AES-256-GCM（WebCrypto に XChaCha が無いため）。鍵は 1 リンク 1 回の使い切り、IV は 96 bit 乱数 | WebCrypto |
| 鍵の導出 | HKDF-SHA256 | WebCrypto |
| 合言葉 | PBKDF2-HMAC-SHA256、60 万回（OWASP の推奨値）、salt 16B、NFC 正規化 | WebCrypto |
| パディング | 長さ 4B＋（名前の長さ 2B＋名前＋本文）＋ゼロを 1 KiB・4 KiB・16 KiB・64 KiB のどれかへ | `app.js` |

```
secret  = random[32]                         # リンクの # の後ろ。サーバに送らない
token   = HKDF(secret, "apikeybin/link/1/token")
key     = HKDF(secret, "apikeybin/link/1/key")
          # 合言葉あり: HKDF(secret || PBKDF2(pass, salt), "apikeybin/link/1/key+pw")
body    = AES-256-GCM(key, iv = random[12], padded, aad = "apikeybin/link/1")
リンク  = https://app.apikeybin.com/s/<id>#1.<secret>  # 合言葉あり: #1p.<secret>
```
**ファイルの名前は暗号文の中に入れる。** サーバからは名前の有無も見えない（パディングで長さも分からない）。名前は UTF-8 で 128 バイトまで。`/`・`\`・`:`、§9.4 の文字を含むもの、前後の空白、末尾の点（保存のときに落ちて `a.html.` が `a.html` になるため）は、作るときも読むときも拒否する。規則は `app.js` と `link.rs` の 2 か所にあり、すべての文字で一致することを試験で確かめる。本文の上限は名前の長さのぶん減る（65,530 バイト − 名前）。

サーバは `SHA-256(token)` だけを持つ。読むには token を出す。**パスだけを知っていても（ログ、履歴の同期、URL を拾うスキャナ）、読むことも消すこともできない。** `app.js` と独立に Python で書いた `verify/web-real/common.py` と、両方向で読み書きして一致を確かめる。

### 19.3 サーバ
- `POST /api/s`: 長さを検査してから読む（96 KiB）。未知のフィールド、規定外の期限、バケット＋タグ以外の長さ、非正規の base64url を拒否。ID は 128 bit 乱数
- `POST /api/s/<id>/open`: `DELETE … WHERE id AND token_hash AND expires_at > now RETURNING …` の 1 文。同時に読んでも 1 人だけが取れる。**読めない理由（開封済み・期限切れ・存在しない・トークン違い）は同じ応答**
- 期限は 10 分・1 時間・1 日・7 日。30 分ごとに期限切れを消す
- 保存するのは暗号文と token の hash と期限だけ。IP も作成時刻も保存しない。日ごとの件数（作成、開封、枠のツールの読み込み）だけ数える。Workers Logs は無効
- `X-Apikeybin` ヘッダ必須、`Sec-Fetch-Site` があれば `same-origin` のみ、CORS なし
- 通報のあったリンクは ID で消す: `npx wrangler d1 execute apikeybin --remote --command "DELETE FROM secrets WHERE id = '<id>'"`。中身は確かめない（読めない）。リンクを持っている人はもともと開いて消せるので、ID だけで消してよい。保存量の数は 30 分ごとの計算で戻る
- 全応答にセキュリティヘッダ（`worker/index.js` と `public/_headers` は同じ値。試験で比べる）。`/s/<id>` は全 ID で同じファイルを返す。何も引かないので、開いても消えず、存在の有無も分からない。**リダイレクトしない**（`#` が転送先へ引き継がれるため）
- 保存量に上限（400 MB。無料の D1 は 500 MB で止まる）。16 KiB を超えるものは、その半分（200 MB）まで。大きいものの洪水が起きても、普通の鍵は送れる
- 要求数に上限（IP ごとの概数。Cloudflare の場所ごとに別に数える）。16 KiB を超えるものは 4 回分に数える

### 19.4 ページ（MUST）
- 第三者のコード、インラインスクリプト、インラインスタイル、外部の画像を置かない。CSP は `default-src 'none'`＋`'self'` だけ。Trusted Types を強制する（3 エンジンとも強制を確認）
- 秘密は `textContent` でしか出さない。`innerHTML` などを使わない（試験で検索する）
- **表示する秘密とリンクをフォーム部品に置かない。** WebKit は `autocomplete="off"` でも `<textarea>` の値を履歴に保存し、「戻る」で復元した（`pagehide` の消去も間に合わない。実測）。`<pre>` に出す。入力欄は `beforeunload` と `pagehide` で消す（これは bfcache の場面のためのもので、試験の環境で再現できず、効き目は未確認。`mutate_web.py` で残る 1 個がこれ）
- 入力欄は `spellcheck="false"`（強化スペルチェックが外へ送るため）、`autocomplete="off"`、`translate="no"`（翻訳で外へ送られるのを防ぐ）
- 受け取る画面に通報のページへのリンクを置く（`https://apikeybin.com/report`）。受け取る画面からサイトへのリンクは、これと新しく作るためのリンクの 2 つだけ
- 「リンクを作る」は、スクリプトの準備ができるまで押せない（押しても何も起きず、何も言わない隙間を作らない）
- 読むのはボタンを押してから。開いただけでは消えない。ボタンを押してから、アドレスバーの鍵を消す
- コピーのボタンを置く。§9.2 のクリップボードの禁止は CLI の話で、ブラウザでは手でコピーするのと露出が同じ。押したときに書くだけで、読まない（`clipboard-read=()`）
- 中身は 64 KiB まで（AWS と Google の秘密の保管庫の上限と同じ）。UTF-8 でないものと NUL を含むものは文字として扱わず、画面に出さず、保存だけにする。CLI も端末には出さず、保存先を聞く。パイプとファイルにはバイトのまま渡す。相手に通知する機能を作らない
- **文字でないファイルを Web から送る機能は閉じてある**（`app.js` の `BINARY_OPEN`）。選ぶとその場で断る。広告の審査のあとで開く。審査はサイト全体が対象で、中身を調べられないファイルの配布を審査の時点で抱えないため。読む側はいつでも扱える。CLI はまだ配っていないので閉じていない。配るのは審査のあと
- ファイルは選ぶほか、作る画面の枠の中へのドラッグでも渡せる。枠の外に落とすと、乗っ取られた広告のプログラムに読まれる（Chromium の実際のドラッグで実測）。枠の中に落としたものは読めなかった。PC ではファイルの欄を点線の枠で示す。スマホでは出さない
- 選んだファイルの中身は入力欄に出さない。送る前は名前だけを見せる
- 保存はバイトのまま、改行も変えない。ページの中では開かない。保存の名前は許可リストで決める。鍵に使う形（`.env`・`.json`・`.yaml`・`.pem`・`.key`・`.txt` など）と拡張子のない名前だけをそのまま使い、ほかは `.txt`（文字でないものは `.bin`）を足して、そのことを画面で伝える。動く種類の一覧を持つと漏れるため（`.py`・`.desktop`・`.fileloc` など）。先頭の点はブラウザが外す（`.env` が `env` に。3 エンジンで実測）ので、これも画面で伝える。CLI は送り手の名前で書かない。名前を表示するだけで、書く先は読む人が `--out` で決める（§8.5）
- `sessionStorage` に置くのは受け取る途中の ID と鍵だけ（試験で検索する）。`app.js` が知っているアドレスは、自分のオリジンと広告のあるページの 2 つだけ（試験で検索する）
- ソースに見えない文字を置かない（双方向制御で読み違えさせる "Trojan Source" のため。正規表現に入った U+2028 でページが動かなくなったこともある。試験で検索する）

### 19.5 守れないもの（README に明記 MUST）
1. **`app.apikeybin.com` の配信元が乗っ取られると盗まれる。** CSP も SRI も攻撃者が書き換えられる（§19.6 で実測）。一般のブラウザで配られたコードを受信者が確かめる手段は拡張機能なしには無い。下げる手段: 専用アカウント＋ハードウェアキー、`verify/web-real/check_live.py` による配信物の見張り、CLI で開く道
2. **`apikeybin.com` の広告スクリプトが乗っ取られると、枠を偽の入力欄に差し替えられる**（実測）。広告主の広告は別の枠で動くので、これは Google のスクリプト自体が乗っ取られた場合の話。画面に書き、広告のない画面を案内する
   - 受け取る人が通る広告のあるページに広告のスクリプトはない（§19.1）。そのページが乗っ取られた場合（`apikeybin.com` の配信元）は、ボタンの行き先を偽の画面に変えられる。鍵と ID はそのページに届かないので、キーそのものは取られない。ただし偽の画面で「リンクを貼ってください」と言われて貼ると取られる。別のリンクへ移して、攻撃者の中身を本物の画面で見せることもできる（中身を信じさせる攻撃）。画面にアドレスを確かめるよう書く
   - そのページのスクリプトは受け取る画面を新しい窓で開ける。Chromium と WebKit ではその窓に `sessionStorage` の写しが入る（実測）。開いた側からは読めず（実測）、開いただけでは読まれない。そこで読むと元のタブでは「使えません」になる
3. 受信端末のマルウェアと拡張機能
4. ブラウザの履歴に鍵つきの URL が残る（Chromium で確認）。読んだあとは無効、読む前に漏れると読まれる。合言葉で下げる
5. ボタンまで押す検査ソフトは、相手より先に消してしまう（Yopass の報告）
6. 偽サイト。名前の似たドメインは防げない
7. 悪用。中身を検査できない。サイズの上限・短い期限・1 回限り・通報の窓口で下げる。同じ設計の Firefox Send はマルウェアの配布に使われて止まった。バイナリを受けるので、テキストのみより恐れは上がる
8. `apikeybin.com` が落ちていると、ブラウザでは受け取れない（広告のあるページを通るため）。記録は消えないので、戻れば読める。`apikeybin open` は影響を受けない
9. 広告のあるページのボタンを新しいタブで開くと、そのタブには鍵がない（`sessionStorage` はタブごと）。「リンクをもう一度開いてください」と出す。実機の iOS Safari と、チャットのアプリの中のブラウザでは確かめていない（3 エンジンの試験だけ）。公開の前に実機で確かめる

### 19.6 測定（`verify/web-threat`）
悪意のあるスクリプトを Chromium・WebKit・Firefox で動かして測った。

| 配置 | 中身と鍵 | その他 |
|---|---|---|
| 秘密のページに第三者スクリプト（CSP なし） | **取れる** | 入力中の文字も取れる |
| 秘密のページに第三者スクリプト（CSP で配信元だけ許可） | **取れる** | 許可した配信元へ送れる |
| 秘密のページに別オリジンの iframe | 取れない | 広告を押すとページごと別サイトへ飛ばせる |
| 秘密のページに sandbox iframe | 取れない | 飛ばせない |
| 秘密のページにスクリプトなしの画像とリンクだけ | 取れない | 画像の配信元に見えるのは IP・UA・時刻。SVG の中のスクリプトは動かない |
| 秘密のページに第三者なし、別オリジンのページに第三者 | 取れない | COOP が無いと開いたタブを別サイトへ飛ばせる |
| 第三者スクリプトは最上位、ツールは別オリジンの枠（採用） | 取れない | 枠を偽の入力欄に差し替えることはできる |
| 上と同じ配置で Google の本物のスクリプトを動かす（通信は止めて記録） | 載らない | 広告要求の `url=` は `https://apikeybin.com/` だけ |
| 受け取る人が通る広告のあるページで悪意のあるスクリプトを動かす | 取れない | `location`・`referrer`・`sessionStorage`・`performance`・枠のどれからも ID と鍵は出ない |
| 同じページで Google の本物のスクリプトを動かす（通信は止めて記録） | 載らない | 広告要求の `url=` は `https://apikeybin.com/open` だけ |
| 同じページのスクリプトが受け取る画面を新しい窓で開く | 取れない | 窓の中は読めない（`web-threat/session_probe.py`。実際の HTTP で測定。COOP で切れる） |
| **配信元そのものが乗っ取られた** | **取れる** | CSP も SRI も無力 |

- URL の `#` の後ろはサーバにも Referer にも出ない（`unsafe-url` でも）。ただしページ内のスクリプトからは読める
- サーバの DB が盗まれても暗号文しか無く、改ざんは AEAD で検出される
- 受け取る画面に AdSense のタグを貼ると、広告要求の `url=` に `#` の後ろがそのまま入った（Google の公開スクリプトを、外への通信を止めたブラウザで動かして確認。応答後の動きと Google 側の扱いは未確認）
