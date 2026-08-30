//! Compile the C++ shim against MP-SPDZ's headers and link its shared library.
//!
//! MP-SPDZ is not vendored and not built here. It is a large C++ tree with its
//! own dependencies (GMP, libsodium, OpenSSL, Boost) and its own build; asking
//! cargo to drive that would put a forty-minute C++ build behind every `cargo
//! check`. Instead the crate points at an existing checkout through
//! `MP_SPDZ_ROOT`, and compiles without the engine when that is unset --- so the
//! workspace still builds on a machine that has no MP-SPDZ, which is most of
//! them.
//!
//! The flags are not written down here. They are asked of MP-SPDZ's own
//! `CONFIG`, because several of them change the layout of the types the shim
//! passes across the boundary: `-DGFP_MOD_SZ=4` sets how many limbs a field
//! element has, `-DUSE_GF2N_LONG` which binary field is compiled in. A shim
//! built without them links against `libSPDZ` without complaint and then reads
//! the wrong bytes out of every object it is handed --- which shows up as a
//! segmentation fault in all seven parties at once, and not as a build error.
//! Reading the flags from the same file the engine's own objects were built
//! from is what makes that class of failure impossible rather than merely
//! unlikely.
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Declared unconditionally, so the compiler can tell a misspelt cfg from an
    // absent engine rather than warning about the one every build without a
    // checkout uses.
    println!("cargo::rustc-check-cfg=cfg(have_spdz)");
    println!("cargo:rerun-if-env-changed=MP_SPDZ_ROOT");
    println!("cargo:rerun-if-changed=shim/qomm_spdz.cpp");
    // And on the engine header the shim compiles against, because that is where
    // `expose-machine-to-embedder.patch` lands. Without this, applying the patch
    // and rebuilding `libSPDZ.so` leaves cargo reporting `Finished` in 0.05s and
    // running the previous shim, which reports "the engine did not call the
    // hook" about a build that now does.
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(&std::env::var("MP_SPDZ_ROOT").unwrap_or_default())
            .join("Processor/OnlineMachine.hpp")
            .display()
    );

    let Some(root) = std::env::var_os("MP_SPDZ_ROOT").map(PathBuf::from) else {
        println!("cargo:warning=MP_SPDZ_ROOT is unset; building without the engine");
        return;
    };
    let root = root.canonicalize().unwrap_or(root);
    if !root.join("libSPDZ.so").exists() && !root.join("libSPDZ.a").exists() {
        println!(
            "cargo:warning=no libSPDZ in {}; run `make libSPDZ.so` there first",
            root.display()
        );
        return;
    }
    println!("cargo:rerun-if-changed={}", root.join("CONFIG").display());

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let object = out.join("qomm_spdz.o");
    let source = std::fs::canonicalize("shim/qomm_spdz.cpp").expect("the shim");

    // Compiled from inside the checkout: CONFIG's include paths are `-I.` and
    // `-I./deps`, which mean the checkout and nowhere else.
    let status = Command::new("c++")
        .current_dir(&root)
        .args(engine_flags(&root))
        .args(["-fPIC", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("a C++ compiler");
    assert!(
        status.success(),
        "the shim did not compile against {}",
        root.display()
    );

    let archive = out.join("libqomm_spdz.a");
    let _ = std::fs::remove_file(&archive); // `ar crs` appends to an existing one
    let status = Command::new("ar")
        .arg("crs")
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("ar");
    assert!(status.success());

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=qomm_spdz");
    println!("cargo:rustc-link-search=native={}", root.display());
    println!("cargo:rustc-link-lib=dylib=SPDZ");
    let engine_ldlibs = config_variable(&root, "LDLIBS");
    // Cargo places `rustc-link-search` paths before linked libraries, whereas
    // a raw `-L...` emitted as `rustc-link-arg` appears after every
    // `rustc-link-lib`. That ordering is observable on a native Apple Silicon
    // host driven by an x86_64 rustup toolchain: MP-SPDZ's Homebrew GMP exists,
    // but `-lgmpxx` is searched before `/opt/homebrew/lib` and the link fails.
    // Promote every search path from MP-SPDZ's own expanded LDLIBS into the
    // Cargo model; the raw flags below remain for rpaths and other linker
    // options.
    for flag in &engine_ldlibs {
        if let Some(path) = flag.strip_prefix("-L").filter(|path| !path.is_empty()) {
            println!("cargo:rustc-link-search=native={path}");
        }
    }
    // The C++ runtime, whose name is not the same everywhere. Apple removed
    // libstdc++ years ago and ships libc++; naming `stdc++` there fails with
    // `library 'stdc++' not found`, which reads like a missing package and is
    // not one.
    let cxx = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        "c++"
    } else {
        "stdc++"
    };
    println!("cargo:rustc-link-lib=dylib={cxx}");
    // The shim is a static archive, so its own GMP references have to be
    // satisfied at the final link. `libSPDZ.so` already depends on GMP, but a
    // shared dependency does not resolve an undefined symbol in an archive that
    // comes before it, and the failure reads as a hundred lines of
    // `gmpxx.h:1597` rather than as a missing `-lgmp`.
    // MP-SPDZ's own `CONFIG` sets
    // `LDLIBS = -lgmpxx -lgmp -lsodium -lssl -lcrypto -lboost_filesystem
    //  -lboost_iostreams`, and the shim reaches all of them through the headers
    // it includes. `libSPDZ.so` depending on the same libraries does not
    // resolve them: an undefined symbol in an archive placed before a shared
    // object stays undefined, and the failure reads as a hundred lines of
    // `gmpxx.h:1597` and `boost::filesystem::detail` rather than as a missing
    // `-lgmp`.
    for lib in [
        "gmpxx",
        "gmp",
        "sodium",
        "ssl",
        "crypto",
        "boost_filesystem",
        "boost_iostreams",
    ] {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", root.display());
    // The rpath is not enough on macOS. MP-SPDZ links `libSPDZ.so` without an
    // `-install_name @rpath/...`, so the library records its own bare name and
    // dyld never consults the rpath at all: the binary links, and then fails at
    // start-up with a page of paths it tried. Saying so at build time is better
    // than letting the reader meet that page.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!(
            "cargo:warning=macOS: run with DYLD_LIBRARY_PATH={}, or give \
                  the engine an @rpath install name once with `install_name_tool \
                  -id @rpath/libSPDZ.so libSPDZ.so`",
            root.display()
        );
    }
    // The shim's own object refers to OpenSSL and Boost directly --- it
    // instantiates the machine, and the machine's templates reach them --- so
    // naming libSPDZ is not enough. The linker does not follow a shared
    // library's own dependencies to resolve someone else's references, and the
    // failure is a page of undefined symbols with names from Boost headers, not
    // anything that mentions MP-SPDZ. Passing the engine's own link line
    // through is both the fix and the guarantee that it stays the same line.
    for flag in engine_ldlibs {
        println!("cargo:rustc-link-arg={flag}");
    }
    println!("cargo:rustc-cfg=have_spdz");
}

/// The flags MP-SPDZ compiled itself with, from MP-SPDZ.
///
/// `CONFIG.mine` is the local override and may not exist; `-include` rather than
/// `include` so a checkout without one still answers. `-Werror` is dropped: the
/// shim is not MP-SPDZ's code and should not be held to MP-SPDZ's warning
/// discipline, and a warning there is not a reason to fail a measurement build.
///
/// The environment is cleared for the call, and that is not caution. MP-SPDZ's
/// CONFIG builds its flags with `CFLAGS += ... $(DEBUG) ...`, and make expands
/// an undefined variable from the environment when it has one. Cargo sets
/// `DEBUG` for every build script --- to `true` or `false`, meaning the Rust
/// profile --- so an inherited environment silently appends the word `false` to
/// the C++ compiler's arguments, where it is read as the name of an input file.
/// Nothing about the resulting error mentions either make or cargo. `PATH` and
/// the caller's unchanged `HOME` are retained because MP-SPDZ's Darwin CONFIG
/// invokes `brew --prefix`; Homebrew refuses to run without HOME and would turn
/// `-L`brew --prefix`/lib` into the unrelated `/lib`.
fn engine_flags(root: &Path) -> Vec<String> {
    let flags = config_variable(root, "CFLAGS");
    // `-DGFP_MOD_SZ` is deliberately not required. An earlier version asserted
    // it was present, on the reasoning that the shim would otherwise mis-read
    // every field element --- but MP-SPDZ's own CONFIG only mentions it in a
    // comment, `Math/gfp.h` defines it to 2 when nothing else does, and the
    // engine's note says it "only needs to be set for primes of bit length more
    // that 256". So a default checkout has no such flag, the assertion fired on
    // the ordinary configuration, and `MP_SPDZ_ROOT=... cargo build -p qomm-mpc`
    // could not succeed on any machine that had not hand-edited CONFIG.mine.
    //
    // What actually has to hold is that the shim and `libSPDZ` agree, and that
    // is already guaranteed by taking the flags from the file the engine's own
    // objects were built from. Adding the flag here when CONFIG does not carry
    // it would *create* the disagreement rather than prevent it.
    // A CFLAGS entry that is not an option is a variable that expanded to
    // something unintended. Caught here it names itself; passed through, it
    // reaches the compiler as a filename and the message is about that.
    if let Some(stray) = flags.iter().find(|f| !f.starts_with('-')) {
        panic!(
            "CONFIG produced the non-option `{stray}` in CFLAGS; \
                some variable it interpolates expanded to that"
        );
    }
    flags.into_iter().filter(|f| f != "-Werror").collect()
}

/// One variable, as MP-SPDZ's own build would expand it.
fn config_variable(root: &Path, name: &str) -> Vec<String> {
    let makefile = format!("include CONFIG\n-include CONFIG.mine\nflags:\n\t@echo $({name})\n");
    let path = PathBuf::from(std::env::var("OUT_DIR").unwrap())
        .join(format!("{}.mk", name.to_lowercase()));
    std::fs::write(&path, &makefile).expect("the flag query");
    let out = Command::new("make")
        .current_dir(root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .arg("-s")
        .arg("-f")
        .arg(&path)
        .arg("flags")
        .output()
        .expect("make, to read MP-SPDZ's own flags");
    assert!(
        out.status.success(),
        "could not read {name} from {}: {}",
        root.join("CONFIG").display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect()
}
