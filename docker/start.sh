#!/bin/bash

for file in conf.json views.py; do
	if [ ! -f /"${1}"/"${file}" ]; then
		echo "No ${file} found, copying to /${1}/"
		cp /fedservice/dc4eu_federation/"${1}"/"${file}" /"${1}"/
	else
		echo "${file} found, leaving alone. Beware when upgrading."

	fi
done
echo "Starting $@."
/fedservice/dc4eu_federation/entity.py "$@"
