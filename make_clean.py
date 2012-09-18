#!/usr/bin/env python
import glob, os
patterns = ['*~', '*.pyc']
dirs = ['.', 'ade']
for d in dirs:
    for p in patterns:
        for _ in glob.glob(p):
            os.unlink(_)
