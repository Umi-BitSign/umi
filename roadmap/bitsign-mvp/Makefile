DOCS = spec design pilot-plan

all: $(DOCS)

$(DOCS): %:
	latexmk -pdf -interaction=nonstopmode $@.tex

clean:
	latexmk -C
	rm -f bitsign-mvp.*

watch-design:
	latexmk -pdf -pvc -interaction=nonstopmode design.tex

watch-pilot:
	latexmk -pdf -pvc -interaction=nonstopmode pilot-plan.tex

.PHONY: all clean watch-design watch-pilot $(DOCS)
