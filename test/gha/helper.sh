#!/bin/bash

TEMP_DIR=$(mktemp -d)

function modify_yaml() {
    local file="${1}"
    local tmp_file="${TEMP_DIR}/values.yaml"
    cp "${file}" "${tmp_file}"

    yq eval-all ".githubConfigUrl = \"${GHA_E2E_CONFIG_URL}\"" -i "${tmp_file}"
    yq eval-all ".githubConfigSecret.github_token = \"${GHA_E2E_GITHUB_TOKEN}\"" -i "${tmp_file}"
    echo "${tmp_file}"
}

function chart_version() {
  cat "${DIR}/../../charts/gha-runner-scale-set/Chart.yaml" | yq '.version'
}
