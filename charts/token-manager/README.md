# Token Manager Helm Chart
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/jwt-manager)](https://artifacthub.io/packages/search?repo=jwt-manager)

The JWT Manager Helm Chart is a Kubernetes chart that provides a custom resource definition (CRD) for managing JSON Web Tokens (JWTs) in your Kubernetes cluster. It allows you to create and manage JWTs, and handles the signing process using various encryption algorithms.

The JWT Manager will only only install within a single namespace.

> [!NOTE]  
> This chart and operator is based on the upstream work in the [JWT Manager](https://github.com/chximn/jwt-manager) repository.

## Installing the Chart

To install the JWT Manager chart, follow these steps:

1. Add the Helm repository:

```shell
helm repo add jwt-manager https://osg-htc.github.org/jwt-manager
```

2. Update the Helm repositories:
```shell
helm repo update
```

3. Install the chart with a release name of your choice:
```shell
helm install my-jwt-manager jwt-manager/jwt-manager
```


## Usage
Once the JWT Manager chart is installed, you can start using JWTs and JWT signers in your Kubernetes cluster. The chart provides two custom resource definitions (CRD): JWT and JWTSigner.

### JWT
The JWT CRD allows you to create, update, and delete JWTs. It has the following specification:

* `issuer`: The name of the JWT issuer to use for signing the token.
* `data`: The data to include in the JWT payload.
* `expiryTime`: The expiration time for the JWT. It can be specified in terms of days, hours, or minutes.
* `resignBefore`: The automation resigning time for the JWT. It can be specified in terms of days, hours, or minutes.
* `key`: The key used for encryption. It can be provided as a secret, a config map, or a direct value.
* `algorithm`: The encryption algorithm to use for signing the JWT.
* `keyId`: The key ID to use for signing the JWT.

Example JWT resource:

```yaml
apiVersion: k8s.chximn.pro/v1
kind: JWT
metadata:
  name: my-jwt
spec:
  issuer: my-jwt-signer
  data:
    username: john.doe
    role: admin
  expiryTime:
    days: 1
  resignBefore:
    hours: 5
  algorithm: RS256
  key:
    value: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
      -----END RSA PRIVATE KEY-----
```
