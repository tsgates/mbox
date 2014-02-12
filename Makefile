SHELL=/bin/bash
DEST=/disk/am0/httpd/htdocs/mbox

arch:
	(cd dist/arch && {                                     \
		makepkg -cs -f;                                    \
		scp mbox-$(shell date +%Y%m%d)-1-x86_64.pkg.tar.xz \
		  pdos:${DEST}/mbox-latest-x86_64.pkg.tar.xz;      \
	})

debian:
	(cd dist && {                                          \
		fakeroot ./debian/rules build;                              \
		fakeroot ./debian/rules binary-arch;                        \
		scp ../mbox_0.1_amd64.deb                          \
		  pdos:${DEST}/mbox-latest-amd64.deb;              \
	})

pub:
	pandoc -s -p --no-wrap                         \
	  -T Mbox -f markdown                          \
	  -t html5                                     \
	  --template=doc/template.html                 \
	  --email-obfuscation=javascript doc/NOTE.web  \
	 | ssh pdos "cat > ${DEST}/index.html"

.PHONY: pub arch debian
