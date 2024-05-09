#!/bin/bash

# read from stdin and pretty print the upgrade config from a upgrade proposal

jq -r '.messages[0].plan.info' | jq -r