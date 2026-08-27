PANDOC ?= pandoc
LATEXMK ?= latexmk

MARKDOWN := README.md
FILTER := filters/whitepaper.lua
BODY := specification.tex
ENTRYPOINT := main.tex
BUILD_DIR := build
PDF := UMI-Whitepaper.pdf

.PHONY: all pdf source clean distclean

all: pdf

pdf: $(PDF)

source: $(BODY)

$(BODY): $(MARKDOWN) $(FILTER)
	$(PANDOC) $(MARKDOWN) \
		--from=gfm \
		--to=latex \
		--lua-filter=$(FILTER) \
		--syntax-highlighting=none \
		--wrap=preserve \
		--output=$(BODY)

$(PDF): $(ENTRYPOINT) $(BODY)
	mkdir -p $(BUILD_DIR)
	TZ=UTC SOURCE_DATE_EPOCH=1787788800 $(LATEXMK) \
		-xelatex \
		-interaction=nonstopmode \
		-halt-on-error \
		-file-line-error \
		-outdir=$(BUILD_DIR) \
		-jobname=UMI-Whitepaper \
		$(ENTRYPOINT)
	cp $(BUILD_DIR)/UMI-Whitepaper.pdf $(PDF)

clean:
	$(LATEXMK) -C -outdir=$(BUILD_DIR) -jobname=UMI-Whitepaper $(ENTRYPOINT)

distclean: clean
	rm -f $(PDF)
