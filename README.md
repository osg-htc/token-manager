# Token Manager Helm Chart

The Token Manager Helm Chart is a Kubernetes chart that provides a custom resource definition (CRD) and operator for managing JSON Web Tokens (JWTs) in your Kubernetes cluster. It allows you to create and manage JWTs, and handles the signing process using various encryption algorithms.

The JWT Manager will only only install within a single namespace.

> [!NOTE]  
> This chart and operator is based on the upstream work in the [JWT Manager](https://github.com/chximn/jwt-manager) repository.

## Installing the Chart

To install the Token Manager chart, follow these steps:

1. Add the Helm repository:

```shell
helm repo add token-manager https://osg-htc.github.io/token-manager
```

2. Update the Helm repositories:
```shell
helm repo update
```

3. Install the chart with a release name of your choice:
```shell
helm install my-token-manager token-manager/token-manager
```


## Usage
Once the Token Manager chart is installed, you can start using JWTs in your Kubernetes cluster. The chart provides a custom resource definition (CRD) of the JWT (and others in the future).

### JWT
The JWT CRD allows you to create, update, and delete JWTs. It has the following specification:

* `issuer`: The name of the JWT issuer to use for signing the token.
* `data`: The data to include in the JWT payload.
* `expiryTime`: The expiration time for the JWT. It can be specified in terms of days, hours, or minutes.
* `resignBefore`: The automation resigning time for the JWT before the expiryTime. It can be specified in terms of days, hours, or minutes.  This is the amount of time before the expiration time that the JWT should be resigned.  So an expiry time of 1 day and a resignBefore time of 1 hour would mean that the JWT would be resigned 1 hour before the 24 hour expiration.
* `algorithm`: The encryption algorithm to use for signing the JWT.
* `keyId`: The key ID to use for signing the JWT.
* `key`: The key used for encryption. It can be provided as a secret, a config map, or a direct value.  
  - **Secret**: Specify the key as a Kubernetes secret reference.  
  - **ConfigMap**: Specify the key as a Kubernetes ConfigMap reference.  
  - **Direct Value**: Provide the key directly in the resource specification.

Example JWT resource:

```yaml
apiVersion: tokens.osg-htc.org/v1
kind: JWT
metadata:
  name: my-jwt
spec:
  issuer: https://issuer.example.com/
  keyId: my-jwt-key
  data:
    username: john.doe
    role: admin
    scope: "storage.read:/ storage.create:/"
    sub: john.doe
    aud:
      - "https://wlcg.cern.ch/jwt/v1/any"
    wlcg.ver: "1.0"
  expiryTime:
    days: 1
  resignBefore:
    hours: 5
  keyId: my-jwt-key
  algorithm: ES256
  key:
    value: |
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEIIphQalRpd3lclrnNmbR8df1/iljebEgI/CLxsmfd4GYoAoGCCqGSM49
      AwEHoUQDQgAEdN/1YF8Q1BGJdmL9zWDMi5D+2Nfc6iAAXXFvA88HPElN+eOxHy0m
      D1ygqiC82+ZMBTqt9l5dn6JFpd2AawPi7A==
      -----END EC PRIVATE KEY-----
```

Example using a secret for the key:

```yaml
apiVersion: tokens.osg-htc.org/v1
kind: JWT
metadata:
  name: my-jwt
spec:
  issuer: https://issuer.example.com/
  keyId: my-jwt-key
  data:
    username: john.doe
    role: admin
    scope: "storage.read:/ storage.create:/"
    sub: john.doe
    aud:
      - "https://wlcg.cern.ch/jwt/v1/any"
    wlcg.ver: "1.0"
  expiryTime:
    days: 1
  resignBefore:
    hours: 5
  keyId: my-jwt-key
  algorithm: ES256
  key:
    secretRef:
      name: my-jwt-secret
      key: privateKey
```
