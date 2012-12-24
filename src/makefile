test:
	@echo "Testing @${shell date}"
	@for f in tests/test-*.sh; do		\
		echo "Testing $$f";				\
		./sandbox.py -t $$f;			\
	done

dist:
	;;

libseccomp.so: seccomp.c
	gcc $^ -o $@ --shared -fPIC

bpf-syscall.h: syscall.py
	python2 -c "import syscall; syscall.print_seccomp()" > $@

.PHONY: test dist
