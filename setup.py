#!/usr/bin/env python

from setuptools import setup

__version__ = '0.0.4'

CLASSIFIERS = map(str.strip,
"""Environment :: Console
Environment :: X11 Applications :: GTK
License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)
Natural Language :: English
Operating System :: POSIX :: Linux
Programming Language :: Python
Programming Language :: Python :: 2.7
Topic :: Security
""".splitlines())

entry_points = {
    'console_scripts': [
        'dns-firewall = dns_firewall.main:main',
    ]
}

setup(
    name="dns-firewall",
    version=__version__,
    author="Federico Ceratto",
    author_email="federico.ceratto@gmail.com",
    description="Local DNS Firewall",
    license="AGPLv3+",
    url="https://github.com/FedericoCeratto/dns-firewall",
    long_description="",
    classifiers=CLASSIFIERS,
    keywords="desktop security",
    install_requires=[
        'setproctitle>=1.0.1',
    ],
    packages=['dns_firewall'],
    package_dir={'dns_firewall': 'dns_firewall'},
    platforms=['Linux'],
    zip_safe=False,
    entry_points=entry_points,
    # Used by setup.py bdist to include files in the binary package
    package_data={'dns_firewall': [
        'data/*.png'
    ]},
)
