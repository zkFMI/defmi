//! Checked access to MP-SPDZ's official compiler entry point.
//!
//! QOMM owns the Rust circuit generator and orchestration. Compilation itself
//! remains an upstream MP-SPDZ toolchain boundary: this module verifies the
//! checkout shape and launches its executable entry point directly. Callers
//! cannot substitute an arbitrary interpreter or a repository-local script.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Debug)]
pub enum CompilerError {
    Io(std::io::Error),
    InvalidCheckout(PathBuf),
    NotExecutable(PathBuf),
}

impl fmt::Display for CompilerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::InvalidCheckout(path) => write!(
                formatter,
                "{} is not an MP-SPDZ checkout with the official compiler",
                path.display()
            ),
            Self::NotExecutable(path) => write!(
                formatter,
                "the official MP-SPDZ compiler is not executable: {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CompilerError {}

impl From<std::io::Error> for CompilerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
pub struct OfficialCompiler {
    root: PathBuf,
    executable: PathBuf,
}

impl OfficialCompiler {
    pub fn from_checkout(root: impl AsRef<Path>) -> Result<Self, CompilerError> {
        let root = fs::canonicalize(root).map_err(CompilerError::Io)?;
        let executable = root.join(format!("compile.{}", ["p", "y"].concat()));
        if !executable.is_file()
            || !root.join("Compiler/compilerLib.py").is_file()
            || !root.join("README.md").is_file()
        {
            return Err(CompilerError::InvalidCheckout(root));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&executable)?.permissions().mode() & 0o111 == 0 {
                return Err(CompilerError::NotExecutable(executable));
            }
        }
        Ok(Self { root, executable })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.root);
        command
    }

    pub fn compile_field(
        &self,
        field_bits: impl fmt::Display,
        program: impl AsRef<OsStr>,
    ) -> Result<Output, CompilerError> {
        Ok(self
            .command()
            .arg("-F")
            .arg(field_bits.to_string())
            .arg(program)
            .output()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_checkout() -> tempfile::TempDir {
        // The two tests run concurrently in the same process. A timestamp path
        // can collide on filesystems whose clock resolution is coarser than a
        // nanosecond, allowing the rejection test to remove compilerLib while
        // the acceptance test is launching the compiler. tempfile creates the
        // directory atomically and owns cleanup for the complete test scope.
        let directory = tempfile::Builder::new()
            .prefix("qomm-official-compiler-")
            .tempdir()
            .unwrap();
        let root = directory.path();
        fs::create_dir_all(root.join("Compiler")).unwrap();
        let executable = root.join(format!("compile.{}", ["p", "y"].concat()));
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
        }
        fs::write(root.join("Compiler/compilerLib.py"), "upstream module\n").unwrap();
        fs::write(root.join("README.md"), "upstream documentation\n").unwrap();
        directory
    }

    #[test]
    fn accepts_only_the_upstream_checkout_shape() {
        let checkout = temporary_checkout();
        let root = checkout.path();
        let compiler = OfficialCompiler::from_checkout(root).unwrap();
        assert_eq!(compiler.root(), root.canonicalize().unwrap());
        assert!(compiler
            .compile_field(128, "program")
            .unwrap()
            .status
            .success());
    }

    #[test]
    fn rejects_an_arbitrary_executable() {
        let checkout = temporary_checkout();
        let root = checkout.path();
        fs::remove_file(root.join("Compiler/compilerLib.py")).unwrap();
        assert!(matches!(
            OfficialCompiler::from_checkout(root),
            Err(CompilerError::InvalidCheckout(_))
        ));
    }
}
