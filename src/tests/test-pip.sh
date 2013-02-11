#!/bin/bash
#
# pre: which pip
# pre: test ! -f $HOME/.local/bin/pep8
# pre: test ! -f $HOME/.local/lib/python3.3/site-packages/pep8.py
# post: test -f $SHOME/.local/bin/pep8
# post: test ! -f $HOME/.local/lib/python3.3/site-packages/pep8.py
#

pip search pep8
pip install --user pep8
