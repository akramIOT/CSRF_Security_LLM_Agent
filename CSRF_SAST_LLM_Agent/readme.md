# Custom Lambda Layer Creation for creating LLM Agentic Tools and Mapping to the Agent: 

1) Following are the Sequence of Steps to be followed to build the  Custom AWS Lambda runtime  layer.

#a) Prepare a Docker Environment
mkdir lambda_layer && cd lambda_layer
mkdir python

Prepare the  requirements.txt for the package  dependencies.

#b) Build the layer

docker run -v $(pwd):/lambda-layer -it lambci/lambda:build-python3.8 bash
pip install -r /lambda-layer/requirements.txt -t /lambda-layer/python
exit

#c) Package the Layer

zip -r9 lambda_layer.zip python

#d) Deploy the Layer to AWS and upload the runtime to AWS Cloud.

aws lambda publish-layer-version \
    --layer-name LangChainLayer \
    --zip-file fileb://lambda_layer.zip \
    --compatible-runtimes python3.8 \
    --region us-east-1

#e) Create the Lambda Function  With the Custom Lambda  Layer deployed, you can create a Lambda function that uses this layer.

Written and stored in lambda-layer/python/lambda_function.py  file

#Package the Function
zip -r function.zip lambda_function.py

#Deploy the Lambda Function

aws lambda create-function \
    --function-name LangGraphAgent \
    --zip-file fileb://function.zip \
    --handler lambda_function.lambda_handler \
    --runtime python3.8 \
    --role arn:aws:iam::9xxxxxxxx:role/<> \
    --layers arn:aws:lambda:us-east-1:9xxxxxxxxx:layer:LangChainLayer:1

# Invoke the Lambda Function

We can all now invoke the Lambda function via the AWS Management Console, AWS CLI, or programmatically using the AWS SDK.
Example invocation using AWS CLI:

aws lambda invoke \
    --function-name LangGraphAgent \
    --payload '{"query": "What does  CSRF  Vulnerability Security  Threat  attack do , Could you detect it with an automated  workflow ? "}' \
    output.txt


## CSRF  Vulnerability Scanned Outputs  redirected to  output.txt file in output folder.