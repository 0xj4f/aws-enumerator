#!/bin/bash 

export DOCKER_IMAGE=0xj4f/aws-enumerator:0.1.0
aws sts get-caller-identity
eval "$(aws-sso eval -S adaptive --profile 'aws-profile-name')"
printenv | grep -iE 'AWS_SESSION|AWS_SECRET|AWS_ACCESS'            

docker run --rm \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN \
  -v $(pwd)/reports:/app/reports \
  ${DOCKER_IMAGE} --region eu-west-2
