.PHONY: compile
compile:
	hy2py -o hproxy hproxy

.PHONY: build
build: compile
	hy setup.hy -v bdist_wheel

.PHONY: clean
clean:
	rm -rf build dist hproxy.egg-info
	hy -c "(do (import pathlib [Path] shutil [rmtree]) \
(for [p (.rglob (Path \"hproxy\") \"*.py\")] (.unlink p)) \
(for [p (.rglob (Path \"hproxy\") \"__pycache__\")] (rmtree p)))"
