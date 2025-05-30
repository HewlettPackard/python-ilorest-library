#!/bin/bash
echo "Running pylint and exporting to file"
pylint -f parseable redfish | tee pylint.out
echo "Pylint done!"
