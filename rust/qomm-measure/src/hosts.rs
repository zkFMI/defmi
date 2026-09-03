//! Stable labels for the machines the measurements were taken on.
//!
//! Real host names identify people and networks, so the label is applied where
//! the name is recorded rather than scrubbed before publication --- a
//! repository that is only safe to publish if someone remembers a step is not
//! safe.
//!
//! What used to be here was a second copy of that table, written out in full.
//! There is one table, in `scripts/host_map.txt`, which does not ship, and this
//! module reads it at run time.
//!
//! Absent, it labels nothing and every machine keeps its own name. That is the
//! normal case for anybody who is not us, and it is the right answer for them.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Where the table is, if there is one: `QOMM_HOST_MAP`, else the private file
/// beside the measurement runners.
fn map_path() -> PathBuf {
    if let Ok(path) = std::env::var("QOMM_HOST_MAP") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/host_map.txt")
}

/// Every machine the local table names, or none.
pub fn labels() -> BTreeMap<String, String> {
    labels_from(&map_path())
}

/// The same, from a named file. Split out so the tests can exercise the
/// parsing and the lookup without an environment variable between them ---
/// four tests sharing one variable is a race, and it was one.
pub fn labels_from(path: &std::path::Path) -> BTreeMap<String, String> {
    let mut table = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return table;
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let (Some(name), Some(published)) = (parts.next(), parts.next()) {
            table.insert(name.to_string(), published.to_string());
        }
    }
    table
}

/// The published name for a machine. Unknown machines keep their name.
pub fn label(node: &str) -> String {
    lookup(&labels(), node)
}

/// The lookup itself: exact first, then without a domain, then unchanged.
pub fn lookup(table: &BTreeMap<String, String>, node: &str) -> String {
    let short = node.split('.').next().unwrap_or(node);
    table
        .get(node)
        .or_else(|| table.get(short))
        .cloned()
        .unwrap_or_else(|| node.to_string())
}

/// The label for the machine currently running, for harnesses to record.
///
/// `QOMM_HOST` wins when set, so a run inside a container --- where the node
/// name is a hash that no table can hold --- can still say where it really was.
pub fn this_host() -> String {
    if let Ok(name) = std::env::var("QOMM_HOST") {
        if !name.is_empty() {
            return label(&name);
        }
    }
    label(&node_name())
}

fn node_name() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Everything in the repository except the private table itself.
    ///
    /// This was a list of thirteen top-level directories, and the list was
    /// exist, and it never held the repository's own `.md`, which is where the
    /// exporter takes `REVIEW.md`, `POSITION.md` and the rest from. A writeup
    /// of *this* leak put the leaked name into `REVIEW.md` and the guard had
    /// nothing to say about it. So the rule is stated as the rule: nothing
    /// here carries a real machine name, and `scripts/host_map.txt` is the one
    /// exception because it is the table and it does not ship.
    /// `scripts/remote_hosts.txt`, the Makefile's list of approved build
    /// workers, is private for the same reason and is excluded the same way.
    fn shipped_files(root: &Path) -> Vec<PathBuf> {
        // Build products and pulled data. `tapes` is 189 MB of market data
        // fetched from the data host and ignored by git; reading it to look
        // for a hostname is 189 MB of nothing.
        const SKIP: [&str; 12] = [
            ".git",
            "target",
            "build",
            "local",
            "tapes",
            "__pycache__",
            ".pytest_cache",
            "lib",
            "out",
            "cache",
            "broadcast",
            "superseded",
        ];
        fn visit(path: &Path, root: &Path, output: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(relative) = path.strip_prefix(root) else {
                    continue;
                };
                if relative
                    .components()
                    .any(|part| SKIP.contains(&part.as_os_str().to_string_lossy().as_ref()))
                {
                    continue;
                }
                if path.is_dir() {
                    visit(&path, root, output);
                } else if path.is_file()
                    && relative != Path::new("scripts/host_map.txt")
                    && relative != Path::new("scripts/remote_hosts.txt")
                {
                    output.push(path);
                }
            }
        }
        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    /// A table of machines that do not exist, so the test says what it means
    /// about the lookup without saying anything about anybody's network.
    ///
    /// Written with `std` rather than `tempfile`: this crate has no
    /// dependencies, which is worth more than the few lines that would save.
    fn fixture(tag: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("qomm-host-map-{}-{}.txt", std::process::id(), tag));
        std::fs::write(
            &path,
            concat!(
                "# a comment, and a blank line follows\n",
                "\n",
                "grinder      site-one   # trailing comment\n",
                "kettle.local site-two\n"
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn the_table_is_somewhere_that_does_not_ship() {
        let path = map_path();
        if !path.exists() {
            return;
        }
        assert!(!labels_from(&path).is_empty());
        let private = path.canonicalize().unwrap();
        let rust = repo_root().join("rust").canonicalize().unwrap();
        assert!(!private.starts_with(rust));
        assert!(private.ends_with("scripts/host_map.txt"));
    }

    #[test]
    fn no_real_machine_name_appears_in_a_file_that_ships() {
        let private = labels();
        if private.is_empty() {
            return;
        }
        let root = repo_root();
        let files = shipped_files(&root);
        let mut guilty = Vec::new();
        for path in files {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if private.keys().any(|name| text.contains(name)) {
                guilty.push(path.strip_prefix(&root).unwrap().to_path_buf());
            }
        }
        assert!(
            guilty.is_empty(),
            "a private machine name appears in files that ship: {guilty:?}"
        );
    }

    /// The leak this catches was not a missing rule; the rule was here and one
    /// harness wrote its own four-line `hostname()` beside it, so the label was
    /// never applied and the real node name went into four artifacts and the manifest.
    /// `no_real_machine_name_...` only notices after a run on a named machine
    /// has already written one. This notices when the code is written, and it
    /// states the rule --- one asker, and it is the one that labels --- rather
    /// than listing the harnesses that currently obey it.
    #[test]
    fn only_this_reader_asks_the_machine_its_name() {
        let root = repo_root();
        let mine = root
            .join("rust/qomm-measure/src/hosts.rs")
            .canonicalize()
            .unwrap();
        let asks = ["Command::new(", "\"hostname\")"].concat();
        let mut guilty = Vec::new();
        for path in shipped_files(&root) {
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            if path.canonicalize().is_ok_and(|p| p == mine) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if text.contains(&asks) {
                guilty.push(path.strip_prefix(&root).unwrap().to_path_buf());
            }
        }
        assert!(
            guilty.is_empty(),
            "these ask the machine its name instead of hosts::this_host(), \
             so what they record is the real name: {guilty:?}"
        );
    }

    #[test]
    fn reader_does_not_embed_a_private_table() {
        let root = repo_root();
        let rust = std::fs::read_to_string(root.join("rust/qomm-measure/src/hosts.rs")).unwrap();
        let forbidden_rust = ["pub const", "LABELS"].join(" ");
        assert!(!rust.contains(&forbidden_rust));
    }

    #[test]
    fn reader_uses_the_configurable_mapping_location() {
        let root = repo_root();
        let rust = std::fs::read_to_string(root.join("rust/qomm-measure/src/hosts.rs")).unwrap();
        for token in ["QOMM_HOST_MAP", "host_map.txt"] {
            assert!(rust.contains(token), "Rust reader omitted {token}");
        }
    }

    #[test]
    fn a_listed_machine_gets_its_label() {
        let path = fixture("listed");
        let table = labels_from(&path);
        assert_eq!(lookup(&table, "grinder"), "site-one");
        // A domain is stripped before the second look, so a machine listed
        // without one is found however it announces itself.
        assert_eq!(lookup(&table, "grinder.internal"), "site-one");
        // One listed *with* `.local` is not in the table under its bare form
        // and is left alone, preserving the mapping contract.
        assert_eq!(lookup(&table, "kettle.local"), "site-two");
        assert_eq!(lookup(&table, "kettle"), "kettle");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unknown_machine_keeps_its_name() {
        let path = fixture("unknown");
        let table = labels_from(&path);
        assert_eq!(
            lookup(&table, "somebody-elses-laptop"),
            "somebody-elses-laptop"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_table_means_no_labelling_rather_than_a_failure() {
        let table = labels_from(Path::new("/nonexistent/host_map.txt"));
        assert!(table.is_empty());
        assert_eq!(lookup(&table, "grinder"), "grinder");
    }

    #[test]
    fn the_environment_can_say_where_a_container_really_is() {
        // The only test here that touches the environment, so nothing races
        // with it over the same two variables.
        let path = fixture("container");
        unsafe {
            std::env::set_var("QOMM_HOST_MAP", &path);
            std::env::set_var("QOMM_HOST", "grinder");
        }
        assert_eq!(this_host(), "site-one");
        unsafe {
            std::env::remove_var("QOMM_HOST");
            std::env::remove_var("QOMM_HOST_MAP");
        }
        let _ = std::fs::remove_file(&path);
    }
}
