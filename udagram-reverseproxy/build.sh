#!/bin/bash
docker build --tag diogosilverio/udagram-reverseproxy:${TRAVIS_BUILD_NUMBER:-latest} .