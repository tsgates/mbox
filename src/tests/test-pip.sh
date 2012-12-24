#!/bin/bash
#
# pre: which pip
# pre: test ! -f ~/.local/lib/python3.3/site-packages/pyquery/pyquery.py
# post: test ! -f ~/.local/lib/python3.3/site-packages/pyquery/pyquery.py
# post: test -f $SHOME/.local/lib/python3.3/site-packages/pyquery/pyquery.py

pip search pyquery
pip install --user pyquery
