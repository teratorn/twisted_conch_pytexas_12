#!/usr/bin/env python
import subprocess, os.path

src = 'conch-slides.md'
dest = os.path.splitext(src)[0] + '.html'

subprocess.Popen(['landslide', '--destination='+dest, '--embed', '-q', src]).wait()

