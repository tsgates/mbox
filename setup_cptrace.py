#!/usr/bin/env python

SOURCES = ['cptrace/cptrace.c']

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: C',
    'Programming Language :: Python',
]

LONG_DESCRIPTION = open('README.cptrace').read()

def main():
    from imp import load_source
    from os import path
    from sys import argv

    if "--setuptools" in argv:
        argv.remove("--setuptools")
        from setuptools import setup, Extension
    else:
        from distutils.core import setup, Extension

    cptrace_ext = Extension('cptrace', sources=SOURCES)

    cptrace = load_source("version", path.join("cptrace", "version.py"))

    install_options = {
        "name": cptrace.PACKAGE,
        "version": cptrace.VERSION,
        "url": cptrace.WEBSITE,
        "download_url": cptrace.WEBSITE,
        "license": cptrace.LICENSE,
        "author": "Victor Stinner",
        "description": "python binding of ptrace written in C",
        "long_description": LONG_DESCRIPTION,
        "classifiers": CLASSIFIERS,
        "ext_modules": [cptrace_ext],
    }
    setup(**install_options)

if __name__ == "__main__":
    main()

