# filefacts Makefile: build, test, lint, fuzz and profile the library and CLI.
# Uses only constructs common to GNU make and BSD make.

BINARY  = filefacts
OUT_DIR = out

# Scrub GNU make's jobserver from cargo's environment. Without this, build
# scripts that spawn their own `make` (e.g. tikv-jemalloc-sys) inherit a
# malformed MAKEFLAGS and fail with "No rule to make target '-j'".
CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

# Where cargo writes its output: $CARGO_TARGET_DIR when set, else `target`.
CARGO_TARGET_DIR ?= target

# Input for the profiling targets: a file or directory to analyse.
BENCH_PATH ?=

FUZZ_TARGET ?= open_all_views

.PHONY: all build release install install-hooks test lint fix fmt clean help bench-build sampled-benchmark heap-build heap-benchmark bench-path fuzz

all: build

help: ## Show this help
	@echo "filefacts Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build              - Build in debug mode (default)"
	@echo "  release            - Build in release mode into $(OUT_DIR)/"
	@echo "  install            - Install release binary to first writeable PATH dir"
	@echo "  install-hooks      - Install the git pre-commit hook (lint + test + Cargo.toml check)"
	@echo "  test               - Run all tests"
	@echo "  lint               - Run rustfmt --check + clippy -D warnings"
	@echo "  fix                - Auto-fix clippy lints, then format with rustfmt"
	@echo "  fmt                - Format code with rustfmt"
	@echo "  fuzz               - Run a cargo-fuzz target (FUZZ_TARGET=$(FUZZ_TARGET); needs nightly)"
	@echo "  bench-build        - Build the profiling-profile binary"
	@echo "  sampled-benchmark  - Profile BENCH_PATH under samply"
	@echo "  heap-build         - Build the profiling binary with jemalloc heap profiling"
	@echo "  heap-benchmark     - Profile BENCH_PATH's heap, writing jeprof dumps"
	@echo "  clean              - Remove build artifacts"
	@echo ""
	@echo "The benchmark targets need BENCH_PATH, e.g. make sampled-benchmark BENCH_PATH=./samples"

build:
	$(CARGO) build

release: $(OUT_DIR)
	$(CARGO) build --release
	cp $(CARGO_TARGET_DIR)/release/$(BINARY) $(OUT_DIR)/$(BINARY)
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY); fi
	@echo "✓ Release binary: $(OUT_DIR)/$(BINARY)"

install: release ## Install binary to first writeable location
	@set -e; \
	if echo "$$PATH" | tr ':' '\n' | grep -qx "$$HOME/.cargo/bin" && [ -d "$$HOME/.cargo/bin" ]; then \
		dest="$$HOME/.cargo/bin/$(BINARY)"; \
	elif [ -d "$$HOME/bin" ] && [ -w "$$HOME/bin" ]; then \
		dest="$$HOME/bin/$(BINARY)"; \
	elif [ -d "$$HOME/.local/bin" ] && [ -w "$$HOME/.local/bin" ]; then \
		dest="$$HOME/.local/bin/$(BINARY)"; \
	elif [ -w /usr/local/bin ]; then \
		dest="/usr/local/bin/$(BINARY)"; \
	else \
		mkdir -p "$$HOME/.cargo/bin"; \
		dest="$$HOME/.cargo/bin/$(BINARY)"; \
	fi; \
	install -m 755 $(OUT_DIR)/$(BINARY) "$$dest.new" && mv -f "$$dest.new" "$$dest"; \
	echo "✓ Installed to $$dest"

install-hooks: ## Install the git pre-commit hook
	@hooks_dir="$$(git rev-parse --git-path hooks)"; \
	mkdir -p "$$hooks_dir"; \
	cp scripts/pre-commit "$$hooks_dir/pre-commit"; \
	chmod +x "$$hooks_dir/pre-commit"; \
	echo "✓ Pre-commit hook installed to $$hooks_dir/pre-commit"

test:
	$(CARGO) test

fmt:
	$(CARGO) fmt --all

# Auto-fix what clippy and rustfmt can fix on their own. Run fmt last so it
# tidies any code clippy rewrote. Mirrors what `lint` checks.
fix:
	$(CARGO) clippy --fix --all-targets --all-features --allow-dirty --allow-staged
	$(CARGO) fmt --all

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --all-targets --all-features -- -D warnings

clean:
	$(CARGO) clean
	rm -rf $(OUT_DIR)

# RSS, time and size limits turn runaway memory, hangs and size-threshold
# paths into reported crashes (see fuzz/README.md).
fuzz: ## Run a cargo-fuzz target with RSS and time limits
	$(CARGO) +nightly fuzz run $(FUZZ_TARGET) -- -rss_limit_mb=2048 -timeout=10 -max_len=1048576

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# ----- profiling -------------------------------------------------------------
# The `profiling` profile is release with full debug info, so samply and
# jeprof can symbolise. Both benchmark targets analyse BENCH_PATH as JSON and
# write stdout/stderr to $(OUT_DIR)/bench.{out,err}.

bench-path:
	@[ -n "$(BENCH_PATH)" ] || { echo "error: set BENCH_PATH to a file or directory to analyse"; exit 1; }
	@[ -e "$(BENCH_PATH)" ] || { echo "error: BENCH_PATH not found: $(BENCH_PATH)"; exit 1; }

bench-build: $(OUT_DIR) ## Build the profiling binary (release + debug symbols)
	$(CARGO) build --profile profiling --bin $(BINARY)
	cp $(CARGO_TARGET_DIR)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).bench
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).bench; fi
	@echo "✓ Benchmark binary: $(OUT_DIR)/$(BINARY).bench"

sampled-benchmark: bench-path bench-build ## Profile BENCH_PATH with samply
	@command -v samply >/dev/null 2>&1 || { echo "error: samply not installed; run: cargo install samply"; exit 1; }
	samply record --save-only -o $(OUT_DIR)/bench.profile.json.gz -- \
		$(OUT_DIR)/$(BINARY).bench --format json "$(BENCH_PATH)" \
		>$(OUT_DIR)/bench.out 2>$(OUT_DIR)/bench.err
	@echo "✓ Profile: $(OUT_DIR)/bench.profile.json.gz  Logs: $(OUT_DIR)/bench.err"

heap-build: $(OUT_DIR) ## Build the profiling binary with jemalloc heap profiling
	$(CARGO) build --profile profiling --features jemalloc-prof --bin $(BINARY)
	cp $(CARGO_TARGET_DIR)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).heap
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).heap; fi
	@echo "✓ Heap-profiling binary: $(OUT_DIR)/$(BINARY).heap"

heap-benchmark: bench-path heap-build ## Profile BENCH_PATH's heap with jemalloc
	@rm -rf $(OUT_DIR)/heap && mkdir -p $(OUT_DIR)/heap
	_RJEM_MALLOC_CONF="prof:true,prof_active:true,prof_final:true,lg_prof_interval:28,prof_prefix:$(OUT_DIR)/heap/jeprof" \
		$(OUT_DIR)/$(BINARY).heap --format json "$(BENCH_PATH)" \
		>$(OUT_DIR)/bench.out 2>$(OUT_DIR)/bench.err
	@echo "✓ Heap profiles: $(OUT_DIR)/heap/jeprof.*.heap"
	@echo "  Analyze with: jeprof --text $(OUT_DIR)/$(BINARY).heap $(OUT_DIR)/heap/jeprof.*.heap"
