.PHONY: compile
compile:
	hy2py -o build/hy2py hproxy

.PHONY: build
build:
	poetry build

.PHONY: clean
clean:
	rm -rf build dist
	hy -c "(do (import pathlib [Path] shutil [rmtree]) \
(for [p (.rglob (Path \"hproxy\") \"__pycache__\")] (rmtree p)))"
