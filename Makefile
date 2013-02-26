SHELL=/bin/bash
DEST=/disk/am0/httpd/htdocs/mbox

dist:
	(cd dist/arch && {                                     \
		makepkg -cs -f;                                    \
		scp mbox-$(shell date +%Y%m%d)-1-x86_64.pkg.tar.xz \
		  am:${DEST}/mbox-latest-1-x86_64.pkg.tar.xz;      \
	})

pub:
	pandoc -s -p --no-wrap                         \
	  -T Mbox -f markdown                          \
	  -t html5                                     \
	  --template=doc/template.html                 \
	  --email-obfuscation=javascript doc/NOTE.web  \
	 | ssh am "cat > ${DEST}/index.html"

.PHONY: dist pub