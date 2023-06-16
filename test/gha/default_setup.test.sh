#!/bin/bash

DIR="$(dirname "${BASH_SOURCE[0]}")"

DIR="$(realpath "${DIR}")"

source "${DIR}/suite.sh"

CTRL_VALUES_YAML="${DIR}/testdata/default-controller-values.yaml"
VALUES_YAML="${DIR}/testdata/default-values.yaml"
SCALE_SET_NAME="$(generate_name "default-setup")"
SCALE_SET_NAMESPACE="arc-runners"

function main() {
    echo "Setting up ARC"

    local failed=()
    VALUES_YAML="${CTRL_VALUES_YAML}" install_arc || failed+=("install_arc")
    VALUES_YAML="${VALUES_YAML}" NAME="${SCALE_SET_NAME}" NAMESPACE="${SCALE_SET_NAMESPACE}" install_scale_set || failed+=("install_scale_set")
    NAME="${SCALE_SET_NAME}" NAMESPACE="${SCALE_SET_NAMESPACE}" uninstall_scale_set || failed+=("uninstall_scale_set")
    uninstall_arc || failed+=("uninstall_arc")
}

main
