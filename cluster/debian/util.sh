#!/bin/bash

# Copyright 2015 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# A library of helper functions that each provider hosting Kubernetes
# must implement to use cluster/kube-*.sh scripts.
set -e

SSH_OPTS="-oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oLogLevel=ERROR"

MASTER=""
MASTER_IP=""
NODE_IPS=""

# Assumed Vars:
#   KUBE_ROOT
function test-build-release() {
  # Make a release
  "${KUBE_ROOT}/build/release.sh"
}

# From user input set the necessary k8s and etcd configuration information
function setClusterInfo() {
  # Initialize NODE_IPS in setClusterInfo function
  # NODE_IPS is defined as a global variable, and is concatenated with other nodeIP
  # When setClusterInfo is called for many times, this could cause potential problems
  # Such as, you will have NODE_IPS=192.168.0.2,192.168.0.3,192.168.0.2,192.168.0.3,
  # which is obviously wrong.
  NODE_IPS=""

  local ii=0
  for i in $nodes; do
    nodeIP=${i#*@}

    if [[ "${roles[${ii}]}" == "ai" ]]; then
      MASTER_IP=$nodeIP
      MASTER=$i
      NODE_IPS="$nodeIP"
    elif [[ "${roles[${ii}]}" == "a" ]]; then
      MASTER_IP=$nodeIP
      MASTER=$i
    elif [[ "${roles[${ii}]}" == "i" ]]; then
      if [[ -z "${NODE_IPS}" ]];then
        NODE_IPS="$nodeIP"
      else
        NODE_IPS="$NODE_IPS,$nodeIP"
      fi
    else
      echo "unsupported role for ${i}. please check"
      exit 1
    fi

    ((ii=ii+1))
  done

}

# Sanity check on $CNI_PLUGIN_CONF and $CNI_PLUGIN_EXES
function check-CNI-config() {
  if [ -z "$CNI_PLUGIN_CONF" ] && [ -n "$CNI_PLUGIN_EXES" ]; then
    echo "Warning: CNI_PLUGIN_CONF is emtpy but CNI_PLUGIN_EXES is not (it is $CNI_PLUGIN_EXES); Flannel will be used" >& 2
  elif [ -n "$CNI_PLUGIN_CONF" ] && [ -z "$CNI_PLUGIN_EXES" ]; then
    echo "Warning: CNI_PLUGIN_EXES is empty but CNI_PLUGIN_CONF is not (it is $CNI_PLUGIN_CONF); Flannel will be used" & 2
  elif [ -n "$CNI_PLUGIN_CONF" ] && [ -n "$CNI_PLUGIN_EXES" ]; then
    local problems=0
    if ! [ -r "$CNI_PLUGIN_CONF" ]; then
      echo "ERROR: CNI_PLUGIN_CONF is set to $CNI_PLUGIN_CONF but that is not a readable existing file!" >& 2
      let problems=1
    fi
    local ii=0
    for exe in $CNI_PLUGIN_EXES; do
      if ! [ -x "$exe" ]; then
        echo "ERROR: CNI_PLUGIN_EXES[$ii], which is $exe, is not an existing executable file!" >& 2
        let problems=problems+1
      fi
      let ii=ii+1
    done
    if (( problems > 0 )); then
      exit 1
    fi
  fi
}


# Verify ssh prereqs
function verify-prereqs() {
  local rc

  rc=0
  ssh-add -L 1> /dev/null 2> /dev/null || rc="$?"
  # "Could not open a connection to your authentication agent."
  if [[ "${rc}" -eq 2 ]]; then
    eval "$(ssh-agent)" > /dev/null
    trap-add "kill ${SSH_AGENT_PID}" EXIT
  fi

  rc=0
  ssh-add -L 1> /dev/null 2> /dev/null || rc="$?"
  # "The agent has no identities."
  if [[ "${rc}" -eq 1 ]]; then
    # Try adding one of the default identities, with or without passphrase.
    ssh-add || true
  fi
  # Expect at least one identity to be available.
  if ! ssh-add -L 1> /dev/null 2> /dev/null; then
    echo "Could not find or add an SSH identity."
    echo "Please start ssh-agent, add your identity, and retry."
    exit 1
  fi
}

# Install handler for signal trap
function trap-add() {
  local handler="$1"
  local signal="${2-EXIT}"
  local cur

  cur="$(eval "sh -c 'echo \$3' -- $(trap -p ${signal})")"
  if [[ -n "${cur}" ]]; then
    handler="${cur}; ${handler}"
  fi

  trap "${handler}" ${signal}
}

function verify-cluster() {
  local ii=0

  for i in ${nodes}
  do
    if [ "${roles[${ii}]}" == "a" ]; then
      verify-master
    elif [ "${roles[${ii}]}" == "i" ]; then
      verify-node "$i"
    elif [ "${roles[${ii}]}" == "ai" ]; then
      verify-master
      verify-node "$i"
    else
      echo "unsupported role for ${i}. please check"
      exit 1
    fi

    ((ii=ii+1))
  done

}

function verify-master() {
  # verify master has all required daemons
  echo -n "Validating master"
  local -a required_daemon=("kube-apiserver" "kube-controller-manager" "kube-scheduler")
  local validated="1"
  local try_count=1
  local max_try_count=30
  until [[ "$validated" == "0" ]]; do
    validated="0"
    local daemon
    for daemon in "${required_daemon[@]}"; do
      ssh $SSH_OPTS "$MASTER" "pgrep -f '${daemon}'" >/dev/null 2>&1 || {
        echo -n "."
        validated="1"
        ((try_count=try_count+1))
        if [[ ${try_count} -gt ${max_try_count} ]]; then
          echo -e "\nWarning: Process '${daemon}' failed to run on ${MASTER}, please check.\n"
          exit 1
        fi
        sleep 2
      }
    done
  done
  echo

}

function verify-node() {
  # verify node has all required daemons
  echo -n "Validating ${1}"
  local -a required_daemon=("kube-proxy" "kubelet" "docker")
  local validated="1"
  local try_count=1
  local max_try_count=30
  until [[ "$validated" == "0" ]]; do
    validated="0"
    local daemon
    for daemon in "${required_daemon[@]}"; do
      ssh $SSH_OPTS "$1" "pgrep -f '${daemon}'" >/dev/null 2>&1 || {
        echo -n "."
        validated="1"
        ((try_count=try_count+1))
        if [[ ${try_count} -gt ${max_try_count} ]]; then
          echo -e "\nWarning: Process '${daemon}' failed to run on ${1}, please check.\n"
          exit 1
        fi
        sleep 2
      }
    done
  done
  echo
}

# Create ~/kube/default/etcd with proper contents.
# $1: The one IP address where the etcd leader listens.
function create-etcd-opts() {
    local etcd_data_dir=/var/lib/etcd/
    mkdir -p ${etcd_data_dir}

    cat <<EOF >/root/kube/cfg/etcd.conf
# [member]
ETCD_NAME=infra
ETCD_DATA_DIR="${etcd_data_dir}/default.etcd"
#ETCD_SNAPSHOT_COUNTER="10000"
#ETCD_HEARTBEAT_INTERVAL="100"
#ETCD_ELECTION_TIMEOUT="1000"
#ETCD_LISTEN_PEER_URLS="http://localhost:2380,http://localhost:7001"
ETCD_LISTEN_CLIENT_URLS="http://127.0.0.1:4001,http://${1}:4001"
#ETCD_MAX_SNAPSHOTS="5"
#ETCD_MAX_WALS="5"
#ETCD_CORS=""
#
#[cluster]
#ETCD_INITIAL_ADVERTISE_PEER_URLS="http://localhost:2380,http://localhost:7001"
# if you use different ETCD_NAME (e.g. test),
# set ETCD_INITIAL_CLUSTER value for this name, i.e. "test=http://..."
#ETCD_INITIAL_CLUSTER="default=http://localhost:2380,default=http://localhost:7001"
#ETCD_INITIAL_CLUSTER_STATE="new"
#ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_ADVERTISE_CLIENT_URLS="http://localhost:2379,http://localhost:4001,http://${1}:4001"
#ETCD_DISCOVERY=""
#ETCD_DISCOVERY_SRV=""
#ETCD_DISCOVERY_FALLBACK="proxy"
#ETCD_DISCOVERY_PROXY=""
#
#[proxy]
#ETCD_PROXY="off"
#
#[security]
#ETCD_CA_FILE=""
#ETCD_CERT_FILE=""
#ETCD_KEY_FILE=""
#ETCD_PEER_CA_FILE=""
#ETCD_PEER_CERT_FILE=""
#ETCD_PEER_KEY_FILE=""
EOF

    cat <<EOF >/etc/systemd/system/etcd.service
[Unit]
Description=Etcd Server
After=network.target

[Service]
Type=notify
WorkingDirectory=${etcd_data_dir}
EnvironmentFile=-/root/kube/cfg/etcd.conf
# set GOMAXPROCS to number of processors
ExecStart=/bin/bash -c "GOMAXPROCS=\$(nproc) /opt/kubernetes/bin/etcd"

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable etcd
}

# Create ~/kube/default/kube-apiserver with proper contents.
# $1: CIDR block for service addresses.
# $2: Admission Controllers to invoke in the API server.
# $3: A port range to reserve for services with NodePort visibility.
# $4: The IP address on which to advertise the apiserver to members of the cluster.
function create-kube-apiserver-opts() {
    local SERVICE_CLUSTER_IP_RANGE=${1}
    local ADMISSION_CONTROL=${2}
    local SERVICE_NODE_PORT_RANGE=${3}
    local ADVERTISE_ADDRESS=${4}

    cat <<EOF >/root/kube/cfg/kube-apiserver
# --logtostderr=true: log to standard error instead of files
KUBE_LOGTOSTDERR="--logtostderr=true"

# --v=0: log level for V logs
KUBE_LOG_LEVEL="--v=4"

# --etcd-servers=[]: List of etcd servers to watch (http://ip:port),
# comma separated. Mutually exclusive with -etcd-config
KUBE_ETCD_SERVERS="--etcd-servers=http://127.0.0.1:4001"

# --insecure-bind-address=127.0.0.1: The IP address on which to serve the --insecure-port.
KUBE_API_ADDRESS="--insecure-bind-address=0.0.0.0"

# --insecure-port=8080: The port on which to serve unsecured, unauthenticated access.
KUBE_API_PORT="--insecure-port=8080"

# --kubelet-port=10250: Kubelet port
NODE_PORT="--kubelet-port=10250"

# --advertise-address=<nil>: The IP address on which to advertise
# the apiserver to members of the cluster.
KUBE_ADVERTISE_ADDR="--advertise-address=${ADVERTISE_ADDRESS}"

# --allow-privileged=false: If true, allow privileged containers.
KUBE_ALLOW_PRIV="--allow-privileged=false"

# --service-cluster-ip-range=<nil>: A CIDR notation IP range from which to assign service cluster IPs.
# This must not overlap with any IP ranges assigned to nodes for pods.
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=${SERVICE_CLUSTER_IP_RANGE}"

KUBE_SERVICE_NODE_PORT_RANGE="--service-node-port-range=${SERVICE_NODE_PORT_RANGE}"

# --admission-control="AlwaysAdmit": Ordered list of plug-ins
# to do admission control of resources into cluster.
# Comma-delimited list of:
#   LimitRanger, AlwaysDeny, SecurityContextDeny, NamespaceExists,
#   NamespaceLifecycle, NamespaceAutoProvision,
#   AlwaysAdmit, ServiceAccount, ResourceQuota
KUBE_ADMISSION_CONTROL="--admission-control=${ADMISSION_CONTROL}"

# --client-ca-file="": If set, any request presenting a client certificate signed
# by one of the authorities in the client-ca-file is authenticated with an identity
# corresponding to the CommonName of the client certificate.
KUBE_API_CLIENT_CA_FILE="--client-ca-file=/srv/kubernetes/ca.crt"

# --tls-cert-file="": File containing x509 Certificate for HTTPS.  (CA cert, if any,
# concatenated after server cert). If HTTPS serving is enabled, and --tls-cert-file
# and --tls-private-key-file are not provided, a self-signed certificate and key are
# generated for the public address and saved to /var/run/kubernetes.
KUBE_API_TLS_CERT_FILE="--tls-cert-file=/srv/kubernetes/server.cert"

# --tls-private-key-file="": File containing x509 private key matching --tls-cert-file.
KUBE_API_TLS_PRIVATE_KEY_FILE="--tls-private-key-file=/srv/kubernetes/server.key"
EOF

KUBE_APISERVER_OPTS="   \${KUBE_LOGTOSTDERR}             \\
                        \${KUBE_LOG_LEVEL}               \\
                        \${KUBE_ETCD_SERVERS}            \\
                        \${KUBE_API_ADDRESS}             \\
                        \${KUBE_API_PORT}                \\
                        \${NODE_PORT}                    \\
                        \${KUBE_ADVERTISE_ADDR}          \\
                        \${KUBE_ALLOW_PRIV}              \\
                        \${KUBE_SERVICE_ADDRESSES}       \\
                        \${KUBE_SERVICE_NODE_PORT_RANGE} \\
                        \${KUBE_ADMISSION_CONTROL}       \\
                        \${KUBE_API_CLIENT_CA_FILE}      \\
                        \${KUBE_API_TLS_CERT_FILE}       \\
                        \${KUBE_API_TLS_PRIVATE_KEY_FILE}"


cat <<EOF >/etc/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/root/kube/cfg/kube-apiserver
ExecStart=/opt/kubernetes/bin/kube-apiserver ${KUBE_APISERVER_OPTS}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable kube-apiserver
}

# Create ~/kube/default/kube-controller-manager with proper contents.
function create-kube-controller-manager-opts() {
    local MASTER_ADDRESS="127.0.0.1"

    cat <<EOF >/root/kube/cfg/kube-controller-manager
KUBE_LOGTOSTDERR="--logtostderr=true"
KUBE_LOG_LEVEL="--v=4"
KUBE_MASTER="--master=${MASTER_ADDRESS}:8080"

# --root-ca-file="": If set, this root certificate authority will be included in
# service account's token secret. This must be a valid PEM-encoded CA bundle.
KUBE_CONTROLLER_MANAGER_ROOT_CA_FILE="--root-ca-file=/srv/kubernetes/ca.crt"

# --service-account-private-key-file="": Filename containing a PEM-encoded private
# RSA key used to sign service account tokens.
KUBE_CONTROLLER_MANAGER_SERVICE_ACCOUNT_PRIVATE_KEY_FILE="--service-account-private-key-file=/srv/kubernetes/server.key"
EOF

    KUBE_CONTROLLER_MANAGER_OPTS="  \${KUBE_LOGTOSTDERR} \\
                                    \${KUBE_LOG_LEVEL}   \\
                                    \${KUBE_MASTER}      \\
                                    \${KUBE_CONTROLLER_MANAGER_ROOT_CA_FILE} \\
                                    \${KUBE_CONTROLLER_MANAGER_SERVICE_ACCOUNT_PRIVATE_KEY_FILE}"

    cat <<EOF >/etc/systemd/system/kube-controller-manager.service
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/root/kube/cfg/kube-controller-manager
ExecStart=/opt/kubernetes/bin/kube-controller-manager ${KUBE_CONTROLLER_MANAGER_OPTS}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable kube-controller-manager
}

# Create ~/kube/default/kube-scheduler with proper contents.
function create-kube-scheduler-opts() {
    local MASTER_ADDRESS="127.0.0.1"

    cat <<EOF >/root/kube/cfg/kube-scheduler
###
# kubernetes scheduler config

# --logtostderr=true: log to standard error instead of files
KUBE_LOGTOSTDERR="--logtostderr=true"

# --v=0: log level for V logs
KUBE_LOG_LEVEL="--v=4"

KUBE_MASTER="--master=${MASTER_ADDRESS}:8080"

# Add your own!
KUBE_SCHEDULER_ARGS=""

EOF

    KUBE_SCHEDULER_OPTS="   \${KUBE_LOGTOSTDERR}     \\
                            \${KUBE_LOG_LEVEL}       \\
                            \${KUBE_MASTER}          \\
                            \${KUBE_SCHEDULER_ARGS}"

    cat <<EOF >/etc/systemd/system/kube-scheduler.service
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/root/kube/cfg/kube-scheduler
ExecStart=/opt/kubernetes/bin/kube-scheduler ${KUBE_SCHEDULER_OPTS}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable kube-scheduler
}

# Create ~/kube/default/kubelet with proper contents.
# $1: The hostname or IP address by which the kubelet will identify itself.
# $2: The one hostname or IP address at which the API server is reached (insecurely).
# $3: If non-empty then the DNS server IP to configure in each pod.
# $4: If non-empty then added to each pod's domain search list.
# $5: Pathname of the kubelet config file or directory.
# $6: If empty then flannel is used otherwise CNI is used.
function create-kubelet-opts() {
    local NODE_ADDRESS=${1}
    local MASTER_ADDRESS=${2}
    local CLUSTER_DNS=${3}
    local CLUSTER_DOMAIN=${4}

    # TODO $5?

    if [ -n "$6" ] ; then
      cni_opts=" --network-plugin=cni --network-plugin-dir=/etc/cni/net.d"
    else
      cni_opts=""
    fi

    cat <<EOF >/root/kube/cfg/kubelet
# --logtostderr=true: log to standard error instead of files
KUBE_LOGTOSTDERR="--logtostderr=true"

#  --v=0: log level for V logs
KUBE_LOG_LEVEL="--v=4"

# --address=0.0.0.0: The IP address for the Kubelet to serve on (set to 0.0.0.0 for all interfaces)
NODE_ADDRESS="--address=${NODE_ADDRESS}"

# --port=10250: The port for the Kubelet to serve on. Note that "kubectl logs" will not work if you set this flag.
NODE_PORT="--port=10250"

# --hostname-override="": If non-empty, will use this string as identification instead of the actual hostname.
NODE_HOSTNAME="--hostname-override=${NODE_ADDRESS}"

# --api-servers=[]: List of Kubernetes API servers for publishing events,
# and reading pods and services. (ip:port), comma separated.
KUBELET_API_SERVER="--api-servers=${MASTER_ADDRESS}:8080"

# --allow-privileged=false: If true, allow containers to request privileged mode. [default=false]
KUBE_ALLOW_PRIV="--allow-privileged=false"

KUBELET_CLUSTER_DNS="--cluster-dns=${CLUSTER_DNS}"
KUBELET_CLUSTER_DOMAIN="--cluster-domain=${CLUSTER_DOMAIN}"

# Add your own!
KUBELET_ARGS="${cni_opts}"
EOF

    KUBE_PROXY_OPTS="   \${KUBE_LOGTOSTDERR}     \\
                        \${KUBE_LOG_LEVEL}       \\
                        \${NODE_ADDRESS}         \\
                        \${NODE_PORT}            \\
                        \${NODE_HOSTNAME}        \\
                        \${KUBELET_API_SERVER}   \\
                        \${KUBE_ALLOW_PRIV}      \\
                        \${KUBELET_ARGS}"

    cat <<EOF >/etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=-/root/kube/cfg/kubelet
ExecStart=/opt/kubernetes/bin/kubelet ${KUBE_PROXY_OPTS}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable kubelet
}

# Create ~/kube/default/kube-proxy with proper contents.
# $1: The hostname or IP address by which the node is identified.
# $2: The one hostname or IP address at which the API server is reached (insecurely).
function create-kube-proxy-opts() {
    local NODE_ADDRESS=${1}
    local MASTER_ADDRESS=${2}

    cat <<EOF >/root/kube/cfg/kube-proxy
# --logtostderr=true: log to standard error instead of files
KUBE_LOGTOSTDERR="--logtostderr=true"

#  --v=0: log level for V logs
KUBE_LOG_LEVEL="--v=4"

# --hostname-override="": If non-empty, will use this string as identification instead of the actual hostname.
NODE_HOSTNAME="--hostname-override=${NODE_ADDRESS}"

# --master="": The address of the Kubernetes API server (overrides any value in kubeconfig)
KUBE_MASTER="--master=http://${MASTER_ADDRESS}:8080"
EOF

    KUBE_PROXY_OPTS="   \${KUBE_LOGTOSTDERR} \\
                        \${KUBE_LOG_LEVEL}   \\
                        \${NODE_HOSTNAME}    \\
                        \${KUBE_MASTER}"

    cat <<EOF >/etc/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Proxy
After=network.target

[Service]
EnvironmentFile=-/root/kube/cfg/kube-proxy
ExecStart=/opt/kubernetes/bin/kube-proxy ${KUBE_PROXY_OPTS}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable kube-proxy
}

# Create ~/kube/default/flanneld with proper contents.
# $1: The one hostname or IP address at which the etcd leader listens.
function create-flanneld-opts() {
    ETCD_SERVERS=${1}
    #FLANNEL_NET=${2:-"172.16.0.0/16"}
    FLANNEL_INTERFACE=${2}


    cat <<EOF >/root/kube/cfg/flannel
FLANNEL_ETCD="-etcd-endpoints=http://${ETCD_SERVERS}:4001"
FLANNEL_ETCD_KEY="-etcd-prefix=/coreos.com/network"
FLANNEL_IP_MASQ="--ip-masq"
FLANNEL_INTERFACE="--iface=${FLANNEL_INTERFACE}""
EOF

    cat <<EOF >/etc/systemd/system/flannel.service
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
Before=docker.service

[Service]
EnvironmentFile=-/root/kube/cfg/flannel
ExecStartPre=/opt/kubernetes/bin/remove-docker0.sh
ExecStart=/opt/kubernetes/bin/flanneld --ip-masq \${FLANNEL_ETCD} \${FLANNEL_ETCD_KEY}
ExecStartPost=/opt/kubernetes/bin/mk-docker-opts.sh -d /run/flannel/docker

Type=notify

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF


# TODO?
# Store FLANNEL_NET to etcd.
#attempt=0
#while true; do
#  /opt/kubernetes/bin/etcdctl --no-sync -C ${ETCD_SERVERS} \
#    get /coreos.com/network/config >/dev/null 2>&1
#  if [[ "$?" == 0 ]]; then
#    break
#  else
#    if (( attempt > 600 )); then
#      echo "timeout for waiting network config" > ~/kube/err.log
#      exit 2
#    fi
#
#    /opt/kubernetes/bin/etcdctl --no-sync -C ${ETCD_SERVERS} \
#      mk /coreos.com/network/config "{\"Network\":\"${FLANNEL_NET}\"}" >/dev/null 2>&1
#    attempt=$((attempt+1))
#    sleep 3
#  fi
#done
#wait

    systemctl daemon-reload
}

# Detect the IP for the master
#
# Assumed vars:
#   MASTER_NAME
# Vars set:
#   KUBE_MASTER_IP
function detect-master() {
  source "${KUBE_CONFIG_FILE}"
  setClusterInfo
  export KUBE_MASTER="${MASTER}"
  export KUBE_MASTER_IP="${MASTER_IP}"
  echo "Using master ${MASTER_IP}"
}

# Detect the information about the nodes
#
# Assumed vars:
#   nodes
# Vars set:
#   KUBE_NODE_IP_ADDRESS (array)
function detect-nodes() {
  source "${KUBE_CONFIG_FILE}"

  KUBE_NODE_IP_ADDRESSES=()
  setClusterInfo

  local ii=0
  for i in ${nodes}
  do
    if [ "${roles[${ii}]}" == "i" ] || [ "${roles[${ii}]}" == "ai" ]; then
      KUBE_NODE_IP_ADDRESSES+=("${i#*@}")
    fi

    ((ii=ii+1))
  done

  if [[ -z "${KUBE_NODE_IP_ADDRESSES[@]}" ]]; then
    echo "Could not detect Kubernetes node nodes.\
    Make sure you've launched a cluster with 'kube-up.sh'" >&2
    exit 1
  fi
}

# Instantiate a kubernetes cluster on debian
function kube-up() {
  export KUBE_CONFIG_FILE=${KUBE_CONFIG_FILE:-${KUBE_ROOT}/cluster/debian/config-default.sh}
  source "${KUBE_CONFIG_FILE}"

  # downloading tarball release
  "${KUBE_ROOT}/cluster/debian/download-release.sh"

  # Fetch the hacked easyrsa that make-ca-cert.sh will use
  curl -L -O https://storage.googleapis.com/kubernetes-release/easy-rsa/easy-rsa.tar.gz > /dev/null 2>&1

  if ! check-CNI-config; then
    return
  fi

  setClusterInfo
  local ii=0

  for i in ${nodes}
  do
    {
      if [ "${roles[${ii}]}" == "a" ]; then
        provision-master
      elif [ "${roles[${ii}]}" == "ai" ]; then
        provision-masterandnode
      elif [ "${roles[${ii}]}" == "i" ]; then
        provision-node "$i"
      else
        echo "unsupported role for ${i}. Please check"
        exit 1
      fi
    }

    ((ii=ii+1))
  done
  wait

  export KUBECTL_PATH="${KUBE_ROOT}/cluster/debian/binaries/kubectl"
  verify-cluster
  detect-master
  export CONTEXT="debian"
  export KUBE_SERVER="http://${KUBE_MASTER_IP}:8080"

  source "${KUBE_ROOT}/cluster/common.sh"

  # set kubernetes user and password
  load-or-gen-kube-basicauth

  create-kubeconfig
}

function provision-master() {

  echo -e "\nDeploying master on machine ${MASTER_IP}"

  ssh $SSH_OPTS "$MASTER" "mkdir -p ~/kube/default"
  ssh $SSH_OPTS "$MASTER" "mkdir -p /root/kube/cfg"

  # copy the binaries and scripts to the ~/kube directory on the master
  scp -r $SSH_OPTS \
    saltbase/salt/generate-cert/make-ca-cert.sh \
    easy-rsa.tar.gz \
    debian/reconfDocker.sh \
    "${KUBE_CONFIG_FILE}" \
    debian/util.sh \
    debian/master/* \
    debian/binaries/master/ \
    "${MASTER}:~/kube"

  if [ -z "$CNI_PLUGIN_CONF" ] || [ -z "$CNI_PLUGIN_EXES" ]; then
    # Flannel is being used: copy the flannel binaries and scripts, set reconf flag
    scp -r $SSH_OPTS debian/master-flannel/* "${MASTER}:~/kube"
    NEED_RECONFIG_DOCKER=true
  else
    # CNI is being used: set reconf flag
    NEED_RECONFIG_DOCKER=false
  fi

  EXTRA_SANS=(
    IP:$MASTER_IP
    IP:${SERVICE_CLUSTER_IP_RANGE%.*}.1
    DNS:kubernetes
    DNS:kubernetes.default
    DNS:kubernetes.default.svc
    DNS:kubernetes.default.svc.cluster.local
  )

  EXTRA_SANS=$(echo "${EXTRA_SANS[@]}" | tr ' ' ,)

  BASH_DEBUG_FLAGS=""
  if [[ "$DEBUG" == "true" ]] ; then
    BASH_DEBUG_FLAGS="set -x"
  fi

  # remote login to MASTER and configue k8s master
  ssh $SSH_OPTS -t "${MASTER}" "
    set +e
    ${BASH_DEBUG_FLAGS}
    source ~/kube/util.sh

    setClusterInfo
    create-etcd-opts '${MASTER_IP}'
    create-kube-apiserver-opts \
      '${SERVICE_CLUSTER_IP_RANGE}' \
      '${ADMISSION_CONTROL}' \
      '${SERVICE_NODE_PORT_RANGE}' \
      '${MASTER_IP}'
    create-kube-controller-manager-opts '${NODE_IPS}'
    create-kube-scheduler-opts
    create-flanneld-opts '127.0.0.1' '${MASTER_IP}'
    FLANNEL_OTHER_NET_CONFIG='${FLANNEL_OTHER_NET_CONFIG}' sudo -E -p '[sudo] password to start master: ' -- /bin/bash -ce '
      ${BASH_DEBUG_FLAGS}

      groupadd -f -r kube-cert
      ${PROXY_SETTING} DEBUG='${DEBUG}' ~/kube/make-ca-cert.sh \"${MASTER_IP}\" \"${EXTRA_SANS}\"
      mkdir -p /opt/kubernetes/bin/
      cp ~/kube/master/* /opt/kubernetes/bin/
      service etcd start
      if ${NEED_RECONFIG_DOCKER}; then FLANNEL_NET=\"${FLANNEL_NET}\" KUBE_CONFIG_FILE=\"${KUBE_CONFIG_FILE}\" DOCKER_OPTS=\"${DOCKER_OPTS}\" ~/kube/reconfDocker.sh a; fi
      '" || {
      echo "Deploying master on machine ${MASTER_IP} failed"
      exit 1
    }
}

function provision-node() {

  echo -e "\nDeploying node on machine ${1#*@}"

  ssh $SSH_OPTS $1 "mkdir -p ~/kube/default"
  ssh $SSH_OPTS $1 "mkdir -p /root/kube/cfg"

  # copy the binaries and scripts to the ~/kube directory on the node
  scp -r $SSH_OPTS \
    "${KUBE_CONFIG_FILE}" \
    debian/util.sh \
    debian/reconfDocker.sh \
    debian/minion/* \
    debian/binaries/minion \
    "${1}:~/kube"

  if [ -z "$CNI_PLUGIN_CONF" ] || [ -z "$CNI_PLUGIN_EXES" ]; then
    # Prep for Flannel use: copy the flannel binaries and scripts, set reconf flag
    scp -r $SSH_OPTS debian/minion-flannel/* "${1}:~/kube"
    SERVICE_STARTS="service flanneld start"
    NEED_RECONFIG_DOCKER=true
    CNI_PLUGIN_CONF=''

  else
    # Prep for CNI use: copy the CNI config and binaries, adjust upstart config, set reconf flag
    ssh $SSH_OPTS "${1}" "rm -rf tmp-cni; mkdir -p tmp-cni/exes tmp-cni/conf"
    scp    $SSH_OPTS "$CNI_PLUGIN_CONF" "${1}:tmp-cni/conf/"
    scp -p $SSH_OPTS  $CNI_PLUGIN_EXES  "${1}:tmp-cni/exes/"
    ssh $SSH_OPTS -t "${1}" '
      sudo -p "[sudo] password to prep node %h: " -- /bin/bash -ce "
        mkdir -p /opt/cni/bin /etc/cni/net.d
        cp ~$(id -un)/tmp-cni/conf/* /etc/cni/net.d/
        cp --preserve=mode ~$(id -un)/tmp-cni/exes/* /opt/cni/bin/
        '"sed -i.bak -e 's/start on started flanneld/start on started ${CNI_KUBELET_TRIGGER}/' -e 's/stop on stopping flanneld/stop on stopping ${CNI_KUBELET_TRIGGER}/' "'~$(id -un)/kube/init_conf/kubelet.conf
        '"sed -i.bak -e 's/start on started flanneld/start on started networking/' -e 's/stop on stopping flanneld/stop on stopping networking/' "'~$(id -un)/kube/init_conf/kube-proxy.conf
        "'
    SERVICE_STARTS='service kubelet    start
                    service kube-proxy start'
    NEED_RECONFIG_DOCKER=false
  fi

  BASH_DEBUG_FLAGS=""
  if [[ "$DEBUG" == "true" ]] ; then
    BASH_DEBUG_FLAGS="set -x"
  fi

  # remote login to node and configue k8s node
  ssh $SSH_OPTS -t "$1" "
    set +e
    ${BASH_DEBUG_FLAGS}
    source ~/kube/util.sh

    setClusterInfo
    create-kubelet-opts \
      '${1#*@}' \
      '${MASTER_IP}' \
      '${DNS_SERVER_IP}' \
      '${DNS_DOMAIN}' \
      '${KUBELET_CONFIG}' \
      '${CNI_PLUGIN_CONF}'
    create-kube-proxy-opts \
      '${1#*@}' \
      '${MASTER_IP}' \
      '${KUBE_PROXY_EXTRA_OPTS}'
    create-flanneld-opts '${MASTER_IP}' '${1#*@}'

    sudo -E -p '[sudo] password to start node: ' -- /bin/bash -ce '
      ${BASH_DEBUG_FLAGS}
      mkdir -p /opt/kubernetes/bin/
      cp ~/kube/minion/* /opt/kubernetes/bin
      ${SERVICE_STARTS}
      if ${NEED_RECONFIG_DOCKER}; then KUBE_CONFIG_FILE=\"${KUBE_CONFIG_FILE}\" DOCKER_OPTS=\"${DOCKER_OPTS}\" ~/kube/reconfDocker.sh i; fi
      '" || {
      echo "Deploying node on machine ${1#*@} failed"
      exit 1
  }
}

function provision-masterandnode() {

  echo -e "\nDeploying master and node on machine ${MASTER_IP}"

  ssh $SSH_OPTS $MASTER "mkdir -p ~/kube/default"
  ssh $SSH_OPTS $MASTER "mkdir -p /root/kube/cfg"

  # copy the binaries and scripts to the ~/kube directory on the master
  # scp order matters
  scp -r $SSH_OPTS \
    saltbase/salt/generate-cert/make-ca-cert.sh \
    easy-rsa.tar.gz \
    "${KUBE_CONFIG_FILE}" \
    debian/util.sh \
    debian/minion/* \
    debian/master/* \
    debian/reconfDocker.sh \
    debian/binaries/master/ \
    debian/binaries/minion \
    "${MASTER}:~/kube"

  if [ -z "$CNI_PLUGIN_CONF" ] || [ -z "$CNI_PLUGIN_EXES" ]; then
    # Prep for Flannel use: copy the flannel binaries and scripts, set reconf flag
    scp -r $SSH_OPTS debian/minion-flannel/* debian/master-flannel/* "${MASTER}:~/kube"
    NEED_RECONFIG_DOCKER=true
    CNI_PLUGIN_CONF=''

  else
    # Prep for CNI use: copy the CNI config and binaries, adjust upstart config, set reconf flag
    ssh $SSH_OPTS "${MASTER}" "rm -rf tmp-cni; mkdir -p tmp-cni/exes tmp-cni/conf"
    scp    $SSH_OPTS "$CNI_PLUGIN_CONF" "${MASTER}:tmp-cni/conf/"
    scp -p $SSH_OPTS  $CNI_PLUGIN_EXES  "${MASTER}:tmp-cni/exes/"
    ssh $SSH_OPTS -t "${MASTER}" '
      sudo -p "[sudo] password to prep master %h: " -- /bin/bash -ce "
        mkdir -p /opt/cni/bin /etc/cni/net.d
        cp ~$(id -un)/tmp-cni/conf/* /etc/cni/net.d/
        cp --preserve=mode ~$(id -un)/tmp-cni/exes/* /opt/cni/bin/
        '"sed -i.bak -e 's/start on started flanneld/start on started etcd/' -e 's/stop on stopping flanneld/stop on stopping etcd/' "'~$(id -un)/kube/init_conf/kube*.conf
        "'
    NEED_RECONFIG_DOCKER=false
  fi

  EXTRA_SANS=(
    IP:${MASTER_IP}
    IP:${SERVICE_CLUSTER_IP_RANGE%.*}.1
    DNS:kubernetes
    DNS:kubernetes.default
    DNS:kubernetes.default.svc
    DNS:kubernetes.default.svc.cluster.local
  )

  EXTRA_SANS=$(echo "${EXTRA_SANS[@]}" | tr ' ' ,)

  BASH_DEBUG_FLAGS=""
  if [[ "$DEBUG" == "true" ]] ; then
    BASH_DEBUG_FLAGS="set -x"
  fi

  # remote login to the master/node and configue k8s
  ssh $SSH_OPTS -t "$MASTER" "
    set +e
    ${BASH_DEBUG_FLAGS}
    source ~/kube/util.sh

    setClusterInfo
    create-etcd-opts '${MASTER_IP}'
    create-kube-apiserver-opts \
      '${SERVICE_CLUSTER_IP_RANGE}' \
      '${ADMISSION_CONTROL}' \
      '${SERVICE_NODE_PORT_RANGE}' \
      '${MASTER_IP}'
    create-kube-controller-manager-opts '${NODE_IPS}'
    create-kube-scheduler-opts
    create-kubelet-opts \
      '${MASTER_IP}' \
      '${MASTER_IP}' \
      '${DNS_SERVER_IP}' \
      '${DNS_DOMAIN}' \
      '${KUBELET_CONFIG}' \
      '${CNI_PLUGIN_CONF}'
    create-kube-proxy-opts \
      '${MASTER_IP}' \
      '${MASTER_IP}' \
      '${KUBE_PROXY_EXTRA_OPTS}'
    create-flanneld-opts '127.0.0.1' '${MASTER_IP}'

    FLANNEL_OTHER_NET_CONFIG='${FLANNEL_OTHER_NET_CONFIG}' sudo -E -p '[sudo] password to start master: ' -- /bin/bash -ce '
      ${BASH_DEBUG_FLAGS}

      groupadd -f -r kube-cert
      ${PROXY_SETTING} DEBUG='${DEBUG}' ~/kube/make-ca-cert.sh \"${MASTER_IP}\" \"${EXTRA_SANS}\"
      mkdir -p /opt/kubernetes/bin/
      cp ~/kube/master/* /opt/kubernetes/bin/
      cp ~/kube/minion/* /opt/kubernetes/bin/

      service etcd start
      if ${NEED_RECONFIG_DOCKER}; then FLANNEL_NET=\"${FLANNEL_NET}\" KUBE_CONFIG_FILE=\"${KUBE_CONFIG_FILE}\" DOCKER_OPTS=\"${DOCKER_OPTS}\" ~/kube/reconfDocker.sh ai; fi
      '" || {
      echo "Deploying master and node on machine ${MASTER_IP} failed"
      exit 1
  }
}

# check whether kubelet has torn down all of the pods
function check-pods-torn-down() {
  local kubectl="${KUBE_ROOT}/cluster/kubectl.sh"
  local attempt=0
  while [[ ! -z "$(kubectl get pods --show-all --all-namespaces| tail -n +2)" ]]; do
    if (( attempt > 120 )); then
      echo "timeout waiting for tearing down pods" >> ~/kube/err.log
    fi
    echo "waiting for tearing down pods"
    attempt=$((attempt+1))
    sleep 5
  done
}

# Delete a kubernetes cluster
function kube-down() {
  export KUBECTL_PATH="${KUBE_ROOT}/cluster/debian/binaries/kubectl"

  export KUBE_CONFIG_FILE=${KUBE_CONFIG_FILE:-${KUBE_ROOT}/cluster/debian/config-default.sh}
  source "${KUBE_CONFIG_FILE}"

  source "${KUBE_ROOT}/cluster/common.sh"

  tear_down_alive_resources
  check-pods-torn-down

  local ii=0
  for i in ${nodes}; do
      if [[ "${roles[${ii}]}" == "ai" || "${roles[${ii}]}" == "a" ]]; then
        echo "Cleaning on master ${i#*@}"
        ssh $SSH_OPTS -t "$i" "
          pgrep etcd && \
          sudo -p '[sudo] password to stop master: ' -- /bin/bash -c '
            service etcd stop

            rm -rf \
              /opt/kubernetes/bin/etcd* \
              /etc/init/etcd.conf \
              /etc/init.d/etcd \
              /etc/default/etcd

            rm -rf /infra*
            rm -rf /srv/kubernetes
            '
        " || echo "Cleaning on master ${i#*@} failed"

        if [[ "${roles[${ii}]}" == "ai" ]]; then
          ssh $SSH_OPTS -t "$i" "sudo rm -rf /var/lib/kubelet"
        fi

      elif [[ "${roles[${ii}]}" == "i" ]]; then
        echo "Cleaning on node ${i#*@}"
        ssh $SSH_OPTS -t "$i" "
          pgrep flanneld && \
          sudo -p '[sudo] password to stop node: ' -- /bin/bash -c '
            service flanneld stop
            rm -rf /var/lib/kubelet
            '
          " || echo "Cleaning on node ${i#*@} failed"
      else
        echo "unsupported role for ${i}"
      fi

      ssh $SSH_OPTS -t "$i" "sudo -- /bin/bash -c '
        rm -f \
          /opt/kubernetes/bin/kube* \
          /opt/kubernetes/bin/flanneld \
          /etc/init/kube* \
          /etc/init/flanneld.conf \
          /etc/init.d/kube* \
          /etc/init.d/flanneld \
          /etc/default/kube* \
          /etc/default/flanneld

        rm -rf ~/kube
        rm -f /run/flannel/subnet.env
      '" || echo "cleaning legacy files on ${i#*@} failed"
    ((ii=ii+1))
  done
}


# Perform common upgrade setup tasks
function prepare-push() {
  # Use local binaries for kube-push
  if [[ -z "${KUBE_VERSION}" ]]; then
    echo "Use local binaries for kube-push"
    if [[ ! -d "${KUBE_ROOT}/cluster/debian/binaries" ]]; then
      echo "No local binaries.Please check"
      exit 1
    else
      echo "Please make sure all the required local binaries are prepared ahead"
      sleep 3
    fi
  else
    # Run download-release.sh to get the required release
    export KUBE_VERSION
    "${KUBE_ROOT}/cluster/debian/download-release.sh"
  fi
}

# Update a kubernetes master with expected release
function push-master() {
  export KUBE_CONFIG_FILE=${KUBE_CONFIG_FILE:-${KUBE_ROOT}/cluster/debian/config-default.sh}
  source "${KUBE_CONFIG_FILE}"

  if [[ ! -f "${KUBE_ROOT}/cluster/debian/binaries/master/kube-apiserver" ]]; then
    echo "There is no required release of kubernetes, please check first"
    exit 1
  fi
  export KUBECTL_PATH="${KUBE_ROOT}/cluster/debian/binaries/kubectl"

  setClusterInfo

  local ii=0
  for i in ${nodes}; do
    if [[ "${roles[${ii}]}" == "a" || "${roles[${ii}]}" == "ai" ]]; then
      echo "Cleaning master ${i#*@}"
      ssh $SSH_OPTS -t "$i" "
        pgrep etcd && sudo -p '[sudo] stop the all process: ' -- /bin/bash -c '
        service etcd stop
        sleep 3
        rm -rf \
          /etc/init/etcd.conf \
          /etc/init/kube* \
          /etc/init/flanneld.conf \
          /etc/init.d/etcd \
          /etc/init.d/kube* \
          /etc/init.d/flanneld \
          /etc/default/etcd \
          /etc/default/kube* \
          /etc/default/flanneld
        rm -f \
          /opt/kubernetes/bin/etcd* \
          /opt/kubernetes/bin/kube* \
          /opt/kubernetes/bin/flanneld
        rm -f /run/flannel/subnet.env
        rm -rf ~/kube
      '" || echo "Cleaning master ${i#*@} failed"
    fi

    if [[ "${roles[${ii}]}" == "a" ]]; then
      provision-master
    elif [[ "${roles[${ii}]}" == "ai" ]]; then
      provision-masterandnode
    elif [[ "${roles[${ii}]}" == "i" ]]; then
      ((ii=ii+1))
      continue
    else
      echo "unsupported role for ${i}, please check"
      exit 1
    fi
    ((ii=ii+1))
  done
  verify-cluster
}

# Update a kubernetes node with expected release
function push-node() {
  export KUBE_CONFIG_FILE=${KUBE_CONFIG_FILE:-${KUBE_ROOT}/cluster/debian/config-default.sh}
  source "${KUBE_CONFIG_FILE}"

  if [[ ! -f "${KUBE_ROOT}/cluster/debian/binaries/minion/kubelet" ]]; then
    echo "There is no required release of kubernetes, please check first"
    exit 1
  fi

  export KUBECTL_PATH="${KUBE_ROOT}/cluster/debian/binaries/kubectl"

  setClusterInfo

  local node_ip=${1}
  local ii=0
  local existing=false

  for i in ${nodes}; do
    if [[ "${roles[${ii}]}" == "i" && ${i#*@} == "$node_ip" ]]; then
      echo "Cleaning node ${i#*@}"
      ssh $SSH_OPTS -t "$i" "
        sudo -p '[sudo] stop the all process: ' -- /bin/bash -c '
          service flanneld stop

          rm -f /opt/kubernetes/bin/kube* \
            /opt/kubernetes/bin/flanneld

          rm -rf \
            /etc/init/kube* \
            /etc/init/flanneld.conf \
            /etc/init.d/kube* \
            /etc/init.d/flanneld \
            /etc/default/kube* \
            /etc/default/flanneld

          rm -f /run/flannel/subnet.env

          rm -rf ~/kube
        '" || echo "Cleaning node ${i#*@} failed"
      provision-node "$i"
      existing=true
    elif [[ "${roles[${ii}]}" == "a" || "${roles[${ii}]}" == "ai" ]] && [[ ${i#*@} == "$node_ip" ]]; then
      echo "${i} is master node, please try ./kube-push -m instead"
      existing=true
    elif [[ "${roles[${ii}]}" == "i" || "${roles[${ii}]}" == "a" || "${roles[${ii}]}" == "ai" ]]; then
      ((ii=ii+1))
      continue
    else
      echo "unsupported role for ${i}, please check"
      exit 1
    fi
    ((ii=ii+1))
  done
  if [[ "${existing}" == false ]]; then
    echo "node ${node_ip} does not exist"
  else
    verify-cluster
  fi

}

# Update a kubernetes cluster with expected source
function kube-push() {
  prepare-push
  export KUBE_CONFIG_FILE=${KUBE_CONFIG_FILE:-${KUBE_ROOT}/cluster/debian/config-default.sh}
  source "${KUBE_CONFIG_FILE}"

  if [[ ! -f "${KUBE_ROOT}/cluster/debian/binaries/master/kube-apiserver" ]]; then
    echo "There is no required release of kubernetes, please check first"
    exit 1
  fi

  export KUBECTL_PATH="${KUBE_ROOT}/cluster/debian/binaries/kubectl"
  #stop all the kube's process & etcd
  local ii=0
  for i in ${nodes}; do
     if [[ "${roles[${ii}]}" == "ai" || "${roles[${ii}]}" == "a" ]]; then
       echo "Cleaning on master ${i#*@}"
       ssh $SSH_OPTS -t "$i" "
        pgrep etcd && \
        sudo -p '[sudo] password to stop master: ' -- /bin/bash -c '
          service etcd stop

          rm -rf \
            /opt/kubernetes/bin/etcd* \
            /etc/init/etcd.conf \
            /etc/init.d/etcd \
            /etc/default/etcd
        '" || echo "Cleaning on master ${i#*@} failed"
      elif [[ "${roles[${ii}]}" == "i" ]]; then
        echo "Cleaning on node ${i#*@}"
        ssh $SSH_OPTS -t $i "
        pgrep flanneld && \
        sudo -p '[sudo] password to stop node: ' -- /bin/bash -c '
          service flanneld stop
        '" || echo "Cleaning on node ${i#*@} failed"
      else
        echo "unsupported role for ${i}"
      fi

      ssh $SSH_OPTS -t "$i" "sudo -- /bin/bash -c '
        rm -f \
          /opt/kubernetes/bin/kube* \
          /opt/kubernetes/bin/flanneld

        rm -rf \
          /etc/init/kube* \
          /etc/init/flanneld.conf \
          /etc/init.d/kube* \
          /etc/init.d/flanneld \
          /etc/default/kube* \
          /etc/default/flanneld

        rm -f /run/flannel/subnet.env
        rm -rf ~/kube
      '" || echo "Cleaning legacy files on ${i#*@} failed"
    ((ii=ii+1))
  done

  #provision all nodes,including master & nodes
  setClusterInfo

  local ii=0
  for i in ${nodes}; do
    if [[ "${roles[${ii}]}" == "a" ]]; then
      provision-master
    elif [[ "${roles[${ii}]}" == "i" ]]; then
      provision-node "$i"
    elif [[ "${roles[${ii}]}" == "ai" ]]; then
      provision-masterandnode
    else
      echo "unsupported role for ${i}. please check"
      exit 1
    fi
    ((ii=ii+1))
  done
  verify-cluster
}

# Perform preparations required to run e2e tests
function prepare-e2e() {
  echo "Debian doesn't need special preparations for e2e tests" 1>&2
}
