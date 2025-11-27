.PHONY: all build release test clean

all: build

build:
	pip install -e .

release:
	pip install .

test:
	# python ./scripts/test_import.py
	# python ./scripts/test_sync.py
	python ./scripts/test_config.py

clean:
	pip uninstall -y vulnkit

