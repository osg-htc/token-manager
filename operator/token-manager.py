import kopf
import kubernetes.config as k8s_config
import kubernetes.client as k8s_client
from os import getenv
from datetime import datetime, timedelta, timezone
import jwt
import uuid
from base64 import b64decode
import logging
import pytz

logging.basicConfig(level=logging.DEBUG)

API_GROUP = getenv("API_GROUP")
API_GROUP_VERSION = getenv("API_GROUP_VERSION")
JWT_CRD = getenv("JWT_CRD")
NBF_LEEWAY = 60

def create_access_token(data: dict, expires_delta: timedelta, sk, algorithm, kid: str):    
    # update data with expiry time
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta

    # Add a few of the standard claims, exp, nbf, iat, jti
    to_encode.update({
        "exp": expire,
        "nbf": datetime.now(timezone.utc) - timedelta(seconds=NBF_LEEWAY),
        "iat": datetime.now(timezone.utc),
        "jti": uuid.uuid4()
    })
    
    headers = {
        "kid": kid
    }

    # encode jwt
    encoded_jwt = jwt.encode(to_encode, sk, algorithm=algorithm, headers=headers)
    return encoded_jwt

def upsert_secret(secret: k8s_client.V1Secret):
    api_instance = k8s_client.CoreV1Api()
    
    try:
        api_instance.read_namespaced_secret(secret.metadata.name, secret.metadata.namespace)
        api_instance.replace_namespaced_secret(secret.metadata.name, secret.metadata.namespace, secret)
    except k8s_client.exceptions.ApiException as e:
        if e.status != 404:
            raise kopf.TemporaryError("Unexcepted ApiException Error")

        api_instance.create_namespaced_secret(secret.metadata.namespace, secret)

def parse_deltatime(delta: dict) -> timedelta:
    if 'days' in delta:
        return timedelta(days=delta['days'])

    if 'hours' in delta:
        return timedelta(hours=delta['hours'])

    if 'minutes' in delta:
        return timedelta(minutes=delta['minutes'])
    
    raise kopf.TemporaryError("Error occured while parsing: Invalid Expiry Time")


def resolve_jwt_signer_key(keyref: dict):
    api_instance = k8s_client.CoreV1Api()

    if 'secret' in keyref:
        try:
            namespace = keyref['secret']['namespace'] if 'namespace' in keyref['secret'] else 'default'
            name = keyref['secret']['name']
            key = keyref['secret']['key']
            secret = api_instance.read_namespaced_secret(name, namespace)
        except k8s_client.exceptions.ApiException as e:
            if e.status == 404:
                raise kopf.TemporaryError("Secret %s not found in namespace %s" % (name, namespace))
            else:
                raise kopf.TemporaryError("Unexcepted ApiException Error")
        
        return b64decode(secret.data[key])
        
    elif 'configMap' in keyref:
        try:
            namespace = keyref['configMap']['namespace'] if 'namespace' in keyref['configMap'] else 'default'
            name = keyref['configMap']['name']
            key = keyref['configMap']['key']
            configMap = api_instance.read_namespaced_config_map(name, namespace)
        except k8s_client.exceptions.ApiException as e:
            if e.status == 404:
                raise kopf.TemporaryError("ConfigMap %s not found in namespace %s" % (name, namespace))
            else:
                raise kopf.TemporaryError("Unexcepted ApiException Error")
        
        return configMap.data[key]
    
    elif 'value' in keyref:
        return keyref['value']


def create_token_and_upsert_secret(namespace: str, spec: dict):
    algorithm = spec['algorithm']
    sk = resolve_jwt_signer_key(spec['key'])
    kid = spec['keyId']

    token = create_access_token(spec['data'], parse_deltatime(spec['expiryTime']), sk, algorithm, kid)

    key = API_GROUP + '/last-signing-time'
    metadata = k8s_client.V1ObjectMeta(
        #name=spec['secretName'],
        namespace=namespace,
        annotations={
            key: str(datetime.now(timezone.utc).timestamp())
        }
    )
    
    secret = k8s_client.V1Secret(
        api_version="v1",
        kind="Secret",
        string_data={'token':token},
        metadata=metadata
    )
    kopf.harmonize_naming(secret, strict=True, forced=True)

    # Adopt the secret
    kopf.adopt(secret)

    upsert_secret(secret)


# Handlers
# Whether the object is created or updated, we need to create the token and upsert the secret
@kopf.on.create(API_GROUP, API_GROUP_VERSION, JWT_CRD)
def on_create(namespace, spec, body, **kwargs):
    create_token_and_upsert_secret(namespace, spec)

@kopf.on.update(API_GROUP, API_GROUP_VERSION, JWT_CRD)
def on_update(namespace, name, spec, status, **kwargs):
    create_token_and_upsert_secret(namespace, spec)


@kopf.timer(API_GROUP, API_GROUP_VERSION, JWT_CRD, interval=60)
def on_timer_jwt(namespace, name, spec, body, status, **kwargs):
    """
    Every minute, check all the tokens and resign them if needed
    """
    if 'resignBefore' in spec:
        resignBefore = parse_deltatime(spec['resignBefore'])
        expiryTime = parse_deltatime(spec['expiryTime'])

        # make sure it makes sense!
        if resignBefore > expiryTime:
            return
        
        api_instance = k8s_client.CoreV1Api()
        try:
            secret = api_instance.read_namespaced_secret(name, namespace)
            if (API_GROUP + '/last-signing-time') in secret.metadata.annotations:
                secret_created_at = secret.metadata.annotations[API_GROUP + '/last-signing-time']
            else:
                secret_created_at = None
        except k8s_client.exceptions.ApiException as e:
            if e.status == 404:
                secret_created_at = None
            else:
                raise kopf.TemporaryError("Unexcepted ApiException Error")
    
        if secret_created_at is not None:
            now = datetime.utcnow().replace(tzinfo=pytz.utc)
            then = datetime.fromtimestamp(float(secret_created_at)).replace(tzinfo=pytz.utc) + expiryTime
            if now >= then - resignBefore:
                logging.info("Resigned token")
                create_token_and_upsert_secret(namespace, spec)


def load_config():
    try:
        k8s_config.load_kube_config()
    except k8s_config.ConfigException:
        k8s_config.load_incluster_config()

if __name__ == "__main__":
    load_config()