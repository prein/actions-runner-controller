#!/bin/bash

DIR="$(dirname "${BASH_SOURCE[0]}")"

DIR="$(realpath "${DIR}")"

source "${DIR}/helper.sh"

CHART_VERSION="$(chart_version)"

ARC_NS="arc-systems"
ARC_HELM_NAME="arc"

function install_arc() {
    echo "Installing arc"

    helm install "${ARC_HELM_NAME}" \
          --namespace "${ARC_NS}" \
          --create-namespace \
          -f "${VALUES_YAML}" \
          ./charts/gha-runner-scale-set-controller \
            --version "${CHART_VERSION}" \
          --debug

    if [ $? -ne 0 ]; then
        echo "Failed to install arc"
        return 1
    fi

    count=0
    while true; do
      POD_NAME=$(kubectl get pods -n arc-systems -l app.kubernetes.io/name=gha-runner-scale-set-controller -o name)
      if [ -n "$POD_NAME" ]; then
        echo "Pod found: $POD_NAME"
        break
      fi
      if [ "$count" -ge 60 ]; then
        echo "Timeout waiting for controller pod with label app.kubernetes.io/name=gha-runner-scale-set-controller"
        return 1
      fi
      sleep 1
      count=$((count+1))
    done

    echo "Waiting for controller pod to be ready"
    kubectl wait --timeout=30s --for=condition=ready pod -n arc-systems -l app.kubernetes.io/name=gha-runner-scale-set-controller

    kubectl get pod -n arc-systems
    kubectl describe deployment arc-gha-runner-scale-set-controller -n arc-systems
}

function uninstall_arc() {
    helm uninstall "${ARC_HELM_NAME}" \
        --namespace "${ARC_NS}" \
        --debug

    if [ $? -ne 0 ]; then
        echo "Failed to uninstall arc"
        return 1
    fi

    kubectl wait --timeout=30s --for=delete pod -n arc-systems -l app.kubernetes.io/component=controller-manager
}

function arc_log() {
    kubectl logs -n arc-systems -l app.kubernetes.io/name=gha-runner-scale-set-controller
}

function install_scale_set() {
  local temp_values=$(modify_yaml "${VALUES_YAML}")
  helm install "${NAME}" \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    -f "${temp_values}" \
    ./charts/gha-runner-scale-set \
    --version "${CHART_VERSION}" \
    --debug

  local count=0

  while true; do
    local pod_name="$(kubectl get pods -n arc-systems -l actions.github.com/scale-set-name="${NAME}" -o name)"
    if [ -n "$pod_name" ]; then
      echo "Pod found: $pod_name"
      break
    fi
    if [ "$count" -ge 60 ]; then
      echo "Timeout waiting for listener pod with label actions.github.com/scale-set-name=${NAME}"
      exit 1
    fi
    sleep 1
    count=$((count+1))
  done
  kubectl wait --timeout=30s --for=condition=ready pod -n arc-systems -l actions.github.com/scale-set-name="${NAME}"
  kubectl get pod -n arc-systems
}

function uninstall_scale_set() {
    helm uninstall "${NAME}" \
        --namespace "${NAMESPACE}" \
        --debug

    kubectl wait --timeout=10s --for=delete AutoScalingRunnerSet -n "${NAME}" -l app.kubernetes.io/instance="${NAME}"
}

function setup_kind() {
    local name="${1}"

    kind create cluster --name "${name}" #--config "${DIR}/kind-config.yaml"
}

function teardown_kind() {
    local name="${1}"

    kind delete cluster --name "${name}"
}

function generate_name() {
  echo "${1}-$(date +'%M%S')$((($RANDOM + 100) % 100 + 1))"
}
