#!/bin/bash

TEST_NAME=${1}

DIR="$(dirname "${BASH_SOURCE[0]}")"

DIR="$(realpath "${DIR}")"

test_dir=$(realpath "${DIR}"/../../test/gha)

echo $test_dir

TARGETS=()

full_separator="======================================================="
semi_separator="-------------------------------------------------------"

function all_cases() {
  echo "$(find "${test_dir}" -name '*.test.sh' | sed "s#^${test_dir}/##g" | sed "s#.test.sh\$##g" | sort)"
}

function usage() {
  echo "Usage: ${0} [cases...] [--flags...]"
  echo "  Empty argument will run all cases."
  echo "  CASES:"
  for c in $(all_cases); do
    echo "    ${c}"
  done
  echo "  FLAGS:"
  echo "    --config-url: URL to the config file."
  echo "    --github-token: GitHub token to use."

  echo "  ENVS:"
  echo "    GHA_E2E_CONFIG_URL: URL to the config file."
  echo "    GHA_E2E_GITHUB_TOKEN: GitHub token to use."
  echo
  echo "  NOTE:"
  echo "    Flags will override envs."

}

function args() {
  if [[ "${#}" -eq 0 ]]; then
    return 0
  fi

  while [[ $# -gt 0 ]]; do
    arg="${1}"
    case "${arg}" in
      --help)
        usage
        exit 0
        ;;
      --config-url)
        shift
        export GHA_E2E_CONFIG_URL="${1}"
        shift
        ;;
      --github-token)
        shift
        export GHA_E2E_GITHUB_TOKEN="${1}"
        shift
        ;;
      -*)
        echo "Unknown option: ${arg}"
        usage
        exit 1
        ;;
      *)
        if [[ -f "${test_dir}/${arg}.test.sh" ]]; then
          TARGETS+=("${arg}")
        else
          echo "Unknown case: ${arg}"
          usage
          exit 1
        fi
        shift
        ;;
    esac

  done

  if [[ -z "${TARGETS}" ]]; then
    mapfile -t TARGETS < <(all_cases)
  fi
}

function main() {
  local failed=()

  for target in "${TARGETS[@]}"; do
    target="${target%.test.sh}"


    test="${test_dir}/${target}.test.sh"
    if [[ ! -x "${test}" ]]; then
      echo "ERROR: Test ${test} is not executable"
      failed+=("${target}")
    fi

    echo "${full_separator}}"
    echo "Testing ${target}..."
    echo "${semi_separator}"

    if ! "${test_dir}/${target}.test.sh"; then
      echo "${full_separator}"
      echo "ERROR: Test ${target} failed"
      failed+=("${target}")
    else
      echo "${full_separator}"
      echo "SUCCESS: Test ${target} passed"
    fi
  done

  echo "${full_separator}"
  if [[ "${#failed[@]}" -gt 0 ]]; then
    echo "ERROR: ${#failed[@]} tests failed"
    for f in "${failed[@]}"; do
      echo "  ${f}"
    done
    exit 1
  fi
}

args "${@}"

main
