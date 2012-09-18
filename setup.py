# Fetch distribute if the user doesn't already have it
from distribute_setup import use_setuptools
use_setuptools()

from setuptools import setup
import subprocess, os, sys

setup(name="AmpDateEcho",
      version='0.1.5',
      description="Provide Date and Echo services via AMP over SSH",
      author="Eric P. Mangold",
      author_email="eric@twistedmatrix.com",
      packages=['ade'],
      scripts=['run_ade.py', 'run_slave.py',
               'ampdate.py', 'ampecho.py',
               'make_slides.py',
               'make_keys.py'],
      install_requires=['Twisted >= 12.2', 'PyCrypto', 'pyasn1'],
      )

