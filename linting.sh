#!/bin/bash

autopep8 -r --in-place satosa_oidcop
autoflake -r --in-place  --remove-unused-variables --expand-star-imports --remove-all-unused-imports satosa_oidcop

flake8 --count --select=E9,F63,F7,F82 --show-source --statistics satosa_oidcop
flake8 --max-line-length 120 --count --statistics satosa_oidcop
