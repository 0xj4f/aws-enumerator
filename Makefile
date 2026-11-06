# Thin wrapper around scripts/check.sh (the single source of truth for local checks).
TARGETS := setup lint py js golden docs perf findings scan matrix doctor all

.PHONY: $(TARGETS) check help
$(TARGETS):
	@scripts/check.sh $@

check: all

help:
	@scripts/check.sh
