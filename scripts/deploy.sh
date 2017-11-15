#! /bin/bash
#
# deploy.sh
# Copyright (C) 2015 dhilipsiva <dhilipsiva@gmail.com>
#
# Distributed under terms of the MIT license.
#

export CURRENT_BRANCH
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
bumpversion patch
git push origin "$CURRENT_BRANCH:$CURRENT_BRANCH"
git push --tags
rm -rf dist/
python setup.py sdist
twine upload dist/*
