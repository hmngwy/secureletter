### Deploying

1. bumpversion
2. git push

CircleCI should build the zip file, upload resources to S3, and execute `update-stack` on cloudformation.

### Initial AWS Setup

1. Create IAM user for CircleCI, see `.circleci/iam-policy.json`
2. Push to #develop to trigger CircleCi upload resources to S3
3. Create Stack with `cloudformation_stack.yaml`
4. Create SES Receipt Rules with SNS Topics as action for the following
  ```
  register@... into SNS:Topic:registerSESProxy
  subscribe@... into SNS:Topic:subscribeSESProxy
  unsubscribe@... into SNSTopic:unsubscribeSESProxy
  ```
5. Create SES Receipt Rules with S3 Action then Lambda action
  ```
  publish@... into S3:letters then Lambda:publishFn
  ```
