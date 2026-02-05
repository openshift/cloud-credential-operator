# bindata.mk for embedding testdata files

# Auto-detect testdata path based on directory structure
# Since e2e/extension exists (subdirectory mode): test/e2e/extension/testdata
BINDATA_DIR := test/e2e/extension/testdata
TEST_MODULE_DIR := test/e2e/extension

BINDATA_PKG := testdata
BINDATA_OUT := $(BINDATA_DIR)/bindata.go

.PHONY: update-bindata
update-bindata:
	@echo "Generating bindata for testdata files..."
	cd $(TEST_MODULE_DIR) && \
	go-bindata \
		-nocompress \
		-nometadata \
		-prefix "testdata" \
		-pkg $(BINDATA_PKG) \
		-o testdata/bindata.go \
		testdata/...
	@echo "✅ Bindata generated successfully"

.PHONY: verify-bindata
verify-bindata: update-bindata
	@echo "Verifying bindata is up to date..."
	git diff --exit-code $(BINDATA_OUT) || (echo "❌ Bindata is out of date. Run 'make update-bindata'" && exit 1)
	@echo "✅ Bindata is up to date"

# Legacy alias for backward compatibility
.PHONY: bindata
bindata: update-bindata

.PHONY: clean-bindata
clean-bindata:
	@echo "Cleaning bindata..."
	@rm -f $(BINDATA_OUT)
