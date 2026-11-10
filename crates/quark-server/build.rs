//! Ensure `rust-embed` always has a `web/dist` directory at compile time.

use std::path::PathBuf;

const PLACEHOLDER: &str = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Quark Drive Server</title></head>
<body style="font-family:system-ui;padding:2rem">
<h1>前端尚未构建</h1>
<p>请先运行 <code>cd web &amp;&amp; npm install &amp;&amp; npm run build</code>，然后重新编译服务端。</p>
</body></html>
"#;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let dist = manifest.join("../../web/dist");
    std::fs::create_dir_all(&dist).expect("create web/dist");
    let index = dist.join("index.html");
    if !index.exists() {
        std::fs::write(&index, PLACEHOLDER).expect("write placeholder index.html");
    }
    println!("cargo:rerun-if-changed={}", dist.display());
}
