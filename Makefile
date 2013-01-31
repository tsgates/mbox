SHELL=/bin/bash

pub:
	pandoc -s -p --no-wrap                         \
	  -T Mbox -f markdown                          \
	  --email-obfuscation=javascript doc/NOTE.web  \
	 | ssh am "cat > /disk/am0/httpd/htdocs/mbox/index.html"