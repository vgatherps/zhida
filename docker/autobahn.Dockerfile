# Autobahn|Testsuite 25.10.1 (wstest), native arm64. Provenance and evidence: docker/README.md.
# Python 2.7 / PyPy / OpenSSL 1.1 only: do not move the base past bullseye.
FROM pypy:2-7-bullseye@sha256:3164eef9333b814d8cc2fef87c6d65bcdd78ae95e515bf91d4797671c9b933ac

RUN ln -s /usr/local/bin/pypy /usr/local/bin/python

RUN pip install --no-deps 'pip==20.3.4' 'setuptools==44.0.0' 'wheel==0.36.2'

RUN pip install --no-deps 'incremental==16.10.1'

RUN pip install --no-deps 'pycparser==2.21' 'six==1.16.0' 'enum34==1.1.10' 'ipaddress==1.0.23'

RUN pip install --no-deps \
        'attrs==21.4.0' 'Automat==22.10.0' 'constantly==15.1.0' 'hyperlink==21.0.0' \
        'idna==2.10' 'PyHamcrest==1.10.1' 'zope.interface==4.6.0' \
        'pyasn1==0.5.1' 'pyasn1-modules==0.3.0' 'service-identity==18.1.0' \
        'autobahn==0.10.9' 'txaio==2.1.0' 'klein==17.10.0' 'Werkzeug==1.0.1' \
        'Jinja2==2.11.3' 'MarkupSafe==1.1.1' 'typing==3.10.0.0' \
        'unittest2==1.1.0' 'linecache2==1.0.0' 'traceback2==1.4.0'

RUN pip install --no-deps --no-build-isolation 'cryptography==3.3.2'
RUN pip install --no-deps --no-build-isolation 'pyOpenSSL==19.1.0'
RUN pip install --no-deps --no-build-isolation 'Twisted==19.10.0'
RUN pip install --no-deps --no-build-isolation 'autobahntestsuite==25.10.1'

# Base-provided (not pip-installed here): cffi==1.18.0.dev0 greenlet==0.4.13 readline==6.2.4.1
# pip check: the only allowed finding is unittest2's metadata dependency on the argparse
# backport; argparse is in the Python 2.7 stdlib (the probe's resolution never installed it).
RUN wstest --help >/dev/null \
 && python -c 'import argparse' \
 && { pip check 2>/dev/null > /tmp/check.txt || true; } \
 && printf '%s\n' 'unittest2 1.1.0 requires argparse, which is not installed.' \
        | diff -u - /tmp/check.txt \
 && printf '%s\n' \
        attrs==21.4.0 autobahn==0.10.9 autobahntestsuite==25.10.1 Automat==22.10.0 \
        constantly==15.1.0 cryptography==3.3.2 enum34==1.1.10 hyperlink==21.0.0 idna==2.10 \
        incremental==16.10.1 ipaddress==1.0.23 Jinja2==2.11.3 klein==17.10.0 \
        linecache2==1.0.0 MarkupSafe==1.1.1 pip==20.3.4 pyasn1==0.5.1 pyasn1-modules==0.3.0 \
        pycparser==2.21 PyHamcrest==1.10.1 pyOpenSSL==19.1.0 service-identity==18.1.0 \
        setuptools==44.0.0 six==1.16.0 traceback2==1.4.0 Twisted==19.10.0 txaio==2.1.0 \
        typing==3.10.0.0 unittest2==1.1.0 Werkzeug==1.0.1 wheel==0.36.2 zope.interface==4.6.0 \
        | sort -f > /tmp/pinned.txt \
 && pip freeze --all > /tmp/freeze-all.txt \
 && printf '%s\n' cffi==1.18.0.dev0 greenlet==0.4.13 readline==6.2.4.1 > /tmp/base.txt \
 && { grep -v -F -x -f /tmp/base.txt /tmp/freeze-all.txt || true; } | sort -f > /tmp/frozen.txt \
 && diff -u /tmp/pinned.txt /tmp/frozen.txt \
 && rm /tmp/check.txt /tmp/pinned.txt /tmp/freeze-all.txt /tmp/base.txt /tmp/frozen.txt
