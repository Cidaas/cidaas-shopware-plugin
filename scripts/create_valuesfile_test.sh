#!/bin/sh
echo "
name: ${CI_PROJECT_NAME}
namespace: cidaas-nightlybuild-services
replica: 1
imagePullSecret: docker-global-cred
image: $DOCKER_IMAGE
port: 80
runtimeId: wimcon1-dev-01
tenantKey: cidaas-kube-nightlybuild-dev
healthCheckPath: /shopware-ui
cpu:
  min: 100m
  max: 500m
memory:
  min: 128Mi
  max: 512Mi
env:
  SHOP_DOMAIN: kube-nightlybuild-dev.cidaas.de/shopware-ui
ingress:
  - hostname: kube-nightlybuild-dev.cidaas.de
    secretName: kube-nightlybuild-dev.cidaas.de
    paths:
      - /shopware-ui
" > values.yml
