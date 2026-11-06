# APIキー便 (apikeybin)

仕様は `docs/SPEC.md`。実装の前に該当の節を読む。変更するなら先に仕様を直す。

## 実装のルール（SPEC §15）

1. 暗号プリミティブを自作しない。§5 の組み合わせ以外を書かない
2. 新しい依存を追加しない。必要なら理由・代替案・ライセンスを示して止まり、承認を待つ。存在を確かめていない crate 名を使わない
3. 秘密値は `SecretBox` / `Zeroizing` で持ち、`Debug` / `Display` / ログ / エラー / panic に出さない
4. `unsafe` は keystore の FFI 境界のみ。各 `unsafe` に `// SAFETY:` を付ける
5. `unwrap` / `expect` を本番コードで使わない（テストは可）
6. 受信データは長さ上限を検査してから decode する
7. 変更には正常系と改ざん系のテストを必ず含める
8. CLI でクリップボードAPIを使わない（ブラウザ版は SPEC §19.4）
9. 【要確認】は実装前に一次情報で確かめ、結果を仕様に書く
10. 安全の検査を足したら `verify/mutation/mutate.py` にも足す。消しても試験が落ちない検査は、無いのと同じ

## 確かめ方

Rust は `~/.cargo/bin`（シェルの設定は変えていない）。

```
export PATH="$HOME/.cargo/bin:$PATH"
cargo test -p apikeybin-core                     # 試験
cargo clippy -p apikeybin-core --all-targets -- -D warnings
python3 verify/mutation/mutate.py                # 検査を消すと試験が落ちるか
cargo audit && cargo deny check                  # 依存
cd verify/web-threat && .venv/bin/python harness.py   # 悪意のあるスクリプトを 3 ブラウザで
```

ブラウザ版（`web/`）は Node が要る（`NODE_BIN=/opt/homebrew/opt/node@22/bin`。試験は `verify/web-threat/.venv` の Python で流す）。

```
cd verify/web-real
$PY test_api.py        # サーバ（ローカルの D1）
$PY test_browser.py    # 3 ブラウザ＋Python の別実装と相互に読み書き
$PY test_shell.py      # 広告つきのサイトの中のツール。悪意のあるスクリプトと Google の本物のスクリプト
$PY test_cli.py        # CLI の実物。ブラウザ・Python と相互に読み書き
$PY mutate_web.py      # 検査を消すと試験が落ちるか（コピーの上で動く）
$PY mutate_cli.py      # 同じく CLI（ソースを書き換えて戻す。流している間は触らない）
$PY check_live.py URL  # 本番の配信物がリポジトリと同じか
python3 web/tools/preview.py   # スマホと PC を並べて見る（http://127.0.0.1:8766/__preview）
```

`web/` は `app.apikeybin.com`（秘密を扱う・第三者のコードなし）、`site/` は `apikeybin.com`（広告あり・秘密を扱わない）。`web/public` は外部の依存を持たない。足さない。広告を `web/` に入れない。安全の検査を足したら `mutate_web.py` にも足す。

受け取る人は `apikeybin.com/open`（広告あり）を通ってから中身を読む。鍵と ID をそのページに渡さない（URL にも Referer にも載せない）。流れは `docs/SPEC.md` §19.1。

見えない文字（U+2028 や双方向制御）を `\u2028` の形でツールから書くと、実物の文字になってファイルに入ることがある（2026-11-04 に `app.js` の正規表現が壊れた）。試験（`test_api.py`）が検出するが、書くときは `chr()` で組み立てる。

「通った」は成果物と数で確かめる。ランダム試験は 1 回の通過で安心しない（1 ビットの穴は 3 回目の実行で出た）。

## このリポジトリに置かないもの

公開する前提で書く。収益の計画、広告の契約、運営者に関わること、ほかの事業の話は置かない。
