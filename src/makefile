test:
	@echo "Testing @${shell date}"
	@for f in tests/test-*.sh; do		\
		echo "Testing $$f";				\
		./sandbox.py -t $$f;			\
	done

dist:
	;;

.PHONY: test dist
