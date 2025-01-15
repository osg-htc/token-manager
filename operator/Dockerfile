FROM python:3.10
ADD requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
ADD operator.py /app/operator.py
WORKDIR /app
ENV API_GROUP=tokens.osg-htc.org
ENV API_GROUP_VERSION=v1
ENV JWT_CRD=jwts
ENTRYPOINT kopf run --namespace ${NAMESPACE} operator.py