#!/bin/bash

#########################################################################
# CONSUL & VAULT Prerequisites
#########################################################################

echo "CONSUL VAULT - Install prerequisites..."
sudo yum install -y unzip
sudo yum install gcc
sudo yum install -y git
yum install epel-release -y
yum install jq -y
curl -LO https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.10.3.linux-amd64.tar.gz
sudo ln -s /usr/local/go/bin/go /usr/local/bin/go
export GOPATH=$HOME/go
mkdir -p $GOPATH
go get -u github.com/cloudflare/cfssl/cmd/cfssl
go get -u github.com/cloudflare/cfssl/cmd/cfssljson
sudo cp $GOPATH/bin/* /usr/local/bin/

echo "CONSUL VAULT - Create working dirs..."
export CONSULVAULT_WORKDIR=$HOME/consul-vault
mkdir -p $CONSULVAULT_WORKDIR/certs/config
mkdir -p $CONSULVAULT_WORKDIR/consul
mkdir -p $CONSULVAULT_WORKDIR/vault
cd $CONSULVAULT_WORKDIR

echo "CONSUL VAULT - CA root key and certificate..."
cat << EOF | tee certs/config/ca-config.json
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "default": {
        "usages": [
          "signing",
          "key encipherment",
          "server auth",
          "client auth"
        ],
        "expiry": "8760h"
      }
    }
  }
}
EOF

cat << EOF | tee certs/config/ca-csr.json
{
  "hosts": [
    "cluster.local"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "FR",
      "ST": "Paris",
      "L": "Paris"
    }
  ]
}
EOF

cfssl gencert -initca certs/config/ca-csr.json | cfssljson -bare certs/ca

#########################################################################
# CONSUL
#########################################################################

echo "CONSUL - Consul TLS key and certificate..."

cat << EOF | tee certs/config/consul-csr.json
{
  "CN": "server.dc1.cluster.local",
  "hosts": [
    "server.dc1.cluster.local",
    "127.0.0.1"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "FR",
      "ST": "Paris",
      "L": "Paris"
    }
  ]
}
EOF

cfssl gencert -ca=certs/ca.pem -ca-key=certs/ca-key.pem -config=certs/config/ca-config.json -profile=default certs/config/consul-csr.json | cfssljson -bare certs/consul

# Consul client
echo "CONSUL - Install Consul client..."
curl -LO https://releases.hashicorp.com/consul/1.4.0/consul_1.4.0_linux_amd64.zip
sudo unzip consul_1.4.0_linux_amd64.zip -d /usr/local/bin/
consul --version

# Consul server
echo "CONSUL - Consul secret..."
export GOSSIP_ENCRYPTION_KEY=$(consul keygen)
kubectl create secret generic consul --from-literal="gossip-encryption-key=${GOSSIP_ENCRYPTION_KEY}" --from-file=certs/ca.pem --from-file=certs/consul.pem --from-file=certs/consul-key.pem
cat << EOF | tee consul/config.json
{
  "ca_file": "/etc/tls/ca.pem",
  "cert_file": "/etc/tls/consul.pem",
  "key_file": "/etc/tls/consul-key.pem",
  "verify_incoming": true,
  "verify_outgoing": true,
  "verify_server_hostname": true,
  "ports": {
    "https": 8443
  }
}
EOF
kubectl create configmap consul --from-file=consul/config.json

echo "CONSUL - Consul service..."
cat << EOF | tee consul/consul-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: consul
  labels:
    name: consul
spec:
  clusterIP: None
  ports:
    - name: http
      port: 8500
      targetPort: 8500
    - name: https
      port: 8443
      targetPort: 8443
    - name: rpc
      port: 8400
      targetPort: 8400
    - name: serflan-tcp
      protocol: "TCP"
      port: 8301
      targetPort: 8301
    - name: serflan-udp
      protocol: "UDP"
      port: 8301
      targetPort: 8301
    - name: serfwan-tcp
      protocol: "TCP"
      port: 8302
      targetPort: 8302
    - name: serfwan-udp
      protocol: "UDP"
      port: 8302
      targetPort: 8302
    - name: server
      port: 8300
      targetPort: 8300
    - name: consuldns
      port: 8600
      targetPort: 8600
  selector:
    app: consul
EOF

echo "CONSUL - Consul statefulset..."
cat << EOF | tee consul/consul-statefulset.yaml
apiVersion: apps/v1beta1
kind: StatefulSet
metadata:
  name: consul
spec:
  serviceName: consul
  replicas: 1
  template:
    metadata:
      labels:
        app: consul
    spec:
      securityContext:
        fsGroup: 1000
      containers:
        - name: consul
          image: "consul:1.4.0"
          env:
            - name: POD_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP
            - name: GOSSIP_ENCRYPTION_KEY
              valueFrom:
                secretKeyRef:
                  name: consul
                  key: gossip-encryption-key
            - name: NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          args:
            - "agent"
            - "-advertise="
            - "-bind=0.0.0.0"
            - "-bootstrap-expect=1"
            - "-retry-join=consul-0.consul.\$(NAMESPACE).svc.cluster.local"
            - "-client=0.0.0.0"
            - "-config-file=/consul/myconfig/config.json"
            - "-datacenter=dc1"
            - "-data-dir=/consul/data"
            - "-domain=cluster.local"
            - "-encrypt="
            - "-server"
            - "-ui"
            - "-disable-host-node-id"
          volumeMounts:
            - name: config
              mountPath: /consul/myconfig
            - name: tls
              mountPath: /etc/tls
          lifecycle:
            preStop:
              exec:
                command:
                - /bin/sh
                - -c
                - consul leave
          ports:
            - containerPort: 8500
              name: ui-port
            - containerPort: 8400
              name: alt-port
            - containerPort: 53
              name: udp-port
            - containerPort: 8443
              name: https-port
            - containerPort: 8080
              name: http-port
            - containerPort: 8301
              name: serflan
            - containerPort: 8302
              name: serfwan
            - containerPort: 8600
              name: consuldns
            - containerPort: 8300
              name: server
      volumes:
        - name: config
          configMap:
            name: consul
        - name: tls
          secret:
            secretName: consul
EOF

cat << EOF | tee consul/consul-service-nonheadless.yaml
kind: Service
apiVersion: v1
metadata:
  name: consul-nonheadless
spec:
  selector:
    app: consul
  ports:
  - protocol: TCP
    port: 8500
    targetPort: 8500
EOF

kubectl apply -f consul/consul-service.yaml
kubectl apply -f consul/consul-service-nonheadless.yaml
kubectl apply -f consul/consul-statefulset.yaml

read -r -d '' USAGE <<- EOF
CONSUL - Consul installed.
CONSUL - Access to Consul store:
\tK8s forward port:
\t\tkubectl port-forward consul-1 8500:8500
\tOn a duplicate SSH session:
\t\tCheck if Consul single-node cluster is alive:
\t\t\tconsul members
\t\tInsert key/value:
\t\t\tcurl -X PUT http://localhost:8500/v1/kv/mykey -d "true"
\t\tRecursively list the store:
\t\t\tcurl http://localhost:8500/v1/kv/?recurse
\t\tValues are base64 encoded, to decode it:
\t\t\techo "<encoded value>" | base64 --decode\n
EOF
printf "$USAGE"

#########################################################################
# VAULT
#########################################################################


cat << EOF | tee certs/config/vault-csr.json
{
  "hosts": [
    "vault",
    "127.0.0.1"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "FR",
      "ST": "Paris",
      "L": "Paris"
    }
  ]
}
EOF
cfssl gencert -ca=certs/ca.pem -ca-key=certs/ca-key.pem -config=certs/config/ca-config.json -profile=default certs/config/vault-csr.json | cfssljson -bare certs/vault

echo "VAULT - Create k8s secret..."
kubectl create secret generic vault --from-file=certs/ca.pem --from-file=certs/vault.pem --from-file=certs/vault-key.pem
kubectl describe secrets vault

echo "VAULT - Create Vault config as a config map from file..."
cat << EOF | tee vault/config.json
{
  "listener": {
    "tcp":{
      "address": "0.0.0.0:8200",
      "tls_disable": 0,
      "tls_cert_file": "/etc/tls/vault.pem",
      "tls_key_file": "/etc/tls/vault-key.pem"
    }
  },
  "storage": {
    "consul": {
      "address": "consul:8500",
      "path": "vault/",
      "disable_registration": "true",
      "ha_enabled": "true"
    }
  },
  "ui": true
}
EOF

kubectl create configmap vault --from-file=vault/config.json
kubectl describe configmap vault


echo "VAULT - Vault service..."
cat << EOF | tee vault/vault-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: vault
  labels:
    app: vault
spec:
  type: ClusterIP
  ports:
    - port: 8200
      targetPort: 8200
      protocol: TCP
      name: vault
  selector:
    app: vault
EOF

kubectl apply -f vault/vault-service.yaml
kubectl get svc vault

echo "VAULT - Vault deployment..."

cat << EOF | tee vault/vault-deploy.yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: vault
  labels:
    app: vault
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: vault
    spec:
      containers:
      - name: vault
        command: ["vault", "server", "-config", "/vault/config/config.json"]
        image: "vault:0.11.5"
        imagePullPolicy: IfNotPresent
        securityContext:
          capabilities:
            add:
              - IPC_LOCK
        volumeMounts:
          - name: configurations
            mountPath: /vault/config/config.json
            subPath: config.json
          - name: vault
            mountPath: /etc/tls
      - name: consul-vault-agent
        image: "consul:1.4.0"
        env:
          - name: GOSSIP_ENCRYPTION_KEY
            valueFrom:
              secretKeyRef:
                name: consul
                key: gossip-encryption-key
          - name: NAMESPACE
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
        args:
          - "agent"
          - "-retry-join=consul-0.consul.\$(NAMESPACE).svc.cluster.local"
          - "-encrypt=\$(GOSSIP_ENCRYPTION_KEY)"
          - "-domain=cluster.local"
          - "-datacenter=dc1"
          - "-disable-host-node-id"
          - "-node=vault-1"
        volumeMounts:
            - name: config
              mountPath: /consul/myconfig
            - name: tls
              mountPath: /etc/tls
      volumes:
        - name: configurations
          configMap:
            name: vault
        - name: config
          configMap:
            name: consul
        - name: tls
          secret:
            secretName: consul
        - name: vault
          secret:
            secretName: vault
EOF

kubectl apply -f vault/vault-deploy.yaml
kubectl get pods -l app=vault

echo "VAULT - Unseal..."

VAULT_IP=$(kubectl  get svc -l app=vault -o json | jq -r '.items[0].spec.clusterIP')

curl -ks --cacert certs/ca.pem --cert certs/vault.pem --key certs/vault-key.pem https://$VAULT_IP:8200/v1/sys/health | jq

cat << EOF | tee vault/payload.json
{
  "secret_shares": 5,
  "secret_threshold": 3
}
EOF

VAULT_INIT=$(curl -ks --request PUT --data @vault/payload.json --cacert certs/ca.pem --cert certs/vault.pem --key certs/vault-key.pem https://$VAULT_IP:8200/v1/sys/init)

f() { curl -ks --request PUT --cacert certs/ca.pem --cert certs/vault.pem --key certs/vault-key.pem https://$VAULT_IP:8200/v1/sys/unseal --data @- <<END;
{"key": "$1"}
END
}
x=3; echo $VAULT_INIT | jq -r '.keys[]' | while read i; do f $i ; x=$(($x-1)); if [ $x -eq 0 ]; then break; fi ; done

VAULT_TOKEN=$(echo $VAULT_INIT | jq -r '.root_token')

read -r -d '' USAGE <<- EOF
CONSUL - Vault installed.
\tVault keys:
\t\tEnv. var: VAULT_INIT
\tVault Token:
\t\tEnv. var: VAULT_TOKEN
\tVault hostname:
\t\tEnv. var: VAULT_IP
EOF
printf "$USAGE"

curl -ks -H "X-Vault-Token: $VAULT_TOKEN" -H "Content-Type: application/json" --request POST https://$VAULT_IP:8200/v1/secret/data/hello -d '{ "data": { "foo": "world" } }'
curl -ks -H "X-Vault-Token: $VAULT_TOKEN" --request GET https://$VAULT_IP:8200/v1/secret/data/hello

curl -ks -H "X-Vault-Token: $VAULT_TOKEN" -H "Content-Type: application/json" --request POST https://$VAULT_IP:8200/v1/secret/samplevaultconfig/data/hello -d '{ "data": { "foo": "world!" } }'
curl -ks -H "X-Vault-Token: $VAULT_TOKEN" --request GET https://$VAULT_IP:8200/v1/secret/samplevaultconfig/data/hello

curl -ks -H "X-Vault-Token: $VAULT_TOKEN" -H "Content-Type: application/json" --request POST https://$VAULT_IP:8200/v1/secret/samplevaultconfig -d '{"data": "feel welcome"}'
curl -ks -H "X-Vault-Token: $VAULT_TOKEN" --request GET https://$VAULT_IP:8200/v1/secret/samplevaultconfig

