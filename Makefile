.PHONY: all build release test clean

all: build

build:
	pip install -e .

release:
	pip install .

test:
	python scripts/test_import.py

clean:
	pip uninstall -y vulnkit

