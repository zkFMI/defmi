# Orchestration only: all Rust compilation and tests execute on an approved
# remote Linux Docker host, never on the developer laptop.
REMOTE_TEST_HOST ?= softbank-l40s
REMOTE_TEST_SSH_OPTIONS ?= -o BatchMode=yes
REMOTE_TEST_IMAGE ?= qomm-test:rust-1.97.1-mpspdz-9d809599
REMOTE_TEST_COMMAND ?= cargo test --locked --release -j16 -p qomm-defmi -p qomm-avalanche-vm -p zkpi-defmi-sdk
REMOTE_TEST_EXPORTS ?=

.PHONY: remote-test
remote-test:
	@case '$(REMOTE_TEST_HOST)' in softbank-l40s|omenx_ubuntu_zerotier) ;; *) echo 'unapproved test host' >&2; exit 2 ;; esac
	@set -eu; \
	remote_dir="$$(ssh $(REMOTE_TEST_SSH_OPTIONS) '$(REMOTE_TEST_HOST)' 'mktemp -d /tmp/defmi-remote-test.XXXXXX')"; \
	case "$$remote_dir" in /tmp/defmi-remote-test.*) ;; *) exit 2 ;; esac; \
	printf 'DeFMI remote test directory: %s\n' "$$remote_dir"; \
	cleanup() { ssh $(REMOTE_TEST_SSH_OPTIONS) '$(REMOTE_TEST_HOST)' "rm -rf -- '$$remote_dir'" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	rsync -a --compress -e 'ssh $(REMOTE_TEST_SSH_OPTIONS)' --exclude '.git/' --exclude 'target/' --exclude '.runtime/' ./ '$(REMOTE_TEST_HOST)':"$$remote_dir/defmi/"; \
	ssh $(REMOTE_TEST_SSH_OPTIONS) '$(REMOTE_TEST_HOST)' "set -eu; \
	  docker image inspect '$(REMOTE_TEST_IMAGE)' >/dev/null; \
	  find '$$remote_dir/defmi/rust' -type f -name '*.rs' -exec touch -- {} +; \
	  docker run --rm --init --network host \
	    --mount type=bind,src='$$remote_dir/defmi',dst=/workspace \
	    --mount type=volume,src=defmi-cargo-registry,dst=/usr/local/cargo/registry \
	    --mount type=volume,src=defmi-cargo-git,dst=/usr/local/cargo/git \
	    --mount type=volume,src=defmi-test-target,dst=/var/cache/defmi/target \
	    --env CARGO_TARGET_DIR=/var/cache/defmi/target \
	    --workdir /workspace/rust '$(REMOTE_TEST_IMAGE)' sh -c '$(REMOTE_TEST_COMMAND)'"; \
	for relative in $(REMOTE_TEST_EXPORTS); do \
	  case "$$relative" in ''|/*|*..*) exit 2 ;; esac; \
	  test -f "$$relative"; \
	  rsync -a --compress -e 'ssh $(REMOTE_TEST_SSH_OPTIONS)' '$(REMOTE_TEST_HOST)':"$$remote_dir/defmi/$$relative" "$$relative"; \
	done
