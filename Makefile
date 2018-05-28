PACKAGE="$(shell stack list-dependencies --separator='-' | grep keccak)"
LOCAL_DOC_ROOT="$(shell stack path --local-doc-root)"

lint:
	hlint src test

keccak:
	stack build --keccak --no-keccak-deps

test: build
	stack test

build:
	stack install
	stack build

clean:
	rm -rf .stack-work

.PHONY: keccak
