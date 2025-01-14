# AWS Acme Instant Tunnel

[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](./LICENSE)
[![Powered by Modus_Create](https://img.shields.io/badge/powered_by-Modus_Create-blue.svg?longCache=true&style=flat&logo=data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMzIwIDMwMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8cGF0aCBkPSJNOTguODI0IDE0OS40OThjMCAxMi41Ny0yLjM1NiAyNC41ODItNi42MzcgMzUuNjM3LTQ5LjEtMjQuODEtODIuNzc1LTc1LjY5Mi04Mi43NzUtMTM0LjQ2IDAtMTcuNzgyIDMuMDkxLTM0LjgzOCA4Ljc0OS01MC42NzVhMTQ5LjUzNSAxNDkuNTM1IDAgMCAxIDQxLjEyNCAxMS4wNDYgMTA3Ljg3NyAxMDcuODc3IDAgMCAwLTcuNTIgMzkuNjI4YzAgMzYuODQyIDE4LjQyMyA2OS4zNiA0Ni41NDQgODguOTAzLjMyNiAzLjI2NS41MTUgNi41Ny41MTUgOS45MjF6TTY3LjgyIDE1LjAxOGM0OS4xIDI0LjgxMSA4Mi43NjggNzUuNzExIDgyLjc2OCAxMzQuNDggMCA4My4xNjgtNjcuNDIgMTUwLjU4OC0xNTAuNTg4IDE1MC41ODh2LTQyLjM1M2M1OS43NzggMCAxMDguMjM1LTQ4LjQ1OSAxMDguMjM1LTEwOC4yMzUgMC0zNi44NS0xOC40My02OS4zOC00Ni41NjItODguOTI3YTk5Ljk0OSA5OS45NDkgMCAwIDEtLjQ5Ny05Ljg5NyA5OC41MTIgOTguNTEyIDAgMCAxIDYuNjQ0LTM1LjY1NnptMTU1LjI5MiAxODIuNzE4YzE3LjczNyAzNS41NTggNTQuNDUgNTkuOTk3IDk2Ljg4OCA1OS45OTd2NDIuMzUzYy02MS45NTUgMC0xMTUuMTYyLTM3LjQyLTEzOC4yOC05MC44ODZhMTU4LjgxMSAxNTguODExIDAgMCAwIDQxLjM5Mi0xMS40NjR6bS0xMC4yNi02My41ODlhOTguMjMyIDk4LjIzMiAwIDAgMS00My40MjggMTQuODg5QzE2OS42NTQgNzIuMjI0IDIyNy4zOSA4Ljk1IDMwMS44NDUuMDAzYzQuNzAxIDEzLjE1MiA3LjU5MyAyNy4xNiA4LjQ1IDQxLjcxNC01MC4xMzMgNC40Ni05MC40MzMgNDMuMDgtOTcuNDQzIDkyLjQzem01NC4yNzgtNjguMTA1YzEyLjc5NC04LjEyNyAyNy41NjctMTMuNDA3IDQzLjQ1Mi0xNC45MTEtLjI0NyA4Mi45NTctNjcuNTY3IDE1MC4xMzItMTUwLjU4MiAxNTAuMTMyLTIuODQ2IDAtNS42NzMtLjA4OC04LjQ4LS4yNDNhMTU5LjM3OCAxNTkuMzc4IDAgMCAwIDguMTk4LTQyLjExOGMuMDk0IDAgLjE4Ny4wMDguMjgyLjAwOCA1NC41NTcgMCA5OS42NjUtNDAuMzczIDEwNy4xMy05Mi44Njh6IiBmaWxsPSIjRkZGIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiLz4KPC9zdmc+)](https://moduscreate.com)

**AWS Acme Instant Tunnel** is a tool to temporarily grant SSH access via Port 22 for a preconfigured EC2 instance to an authorized & authenticated user.

The [CIS security benchmark for AWS](https://www.cisecurity.org/benchmark/amazon_web_services/) recommends that Port 22 should have no public incoming traffic (0.0.0.0/0), so a problem arises when trying to access instances via SSH. A possible solution to this would be manually adding permissions (access from a specified IP address for example) to a instance's security group, but this could be very error prone and inconsistent. Some enterprises deal with this issue by having people VPN into their corporate network and having people SSH from there. However, this doesn't make sense for many distributed organizations where there is no VPN or granting access to a VPN is not a good idea for those who need to SSH into AWS resources.

AWS Acme Instant Tunnel presents an alternative to the two aforementioned approaches by _automating_ the authorization, management and storage of security group permissions for temporary SSH access.

- [Getting Started](#getting-started)
- [How it Works](#how-it-works)
- [Developing](#developing)
  - [Prerequisites](#prerequisites)
  - [Testing](#testing)
  - [Contributing](#contributing)
- [Modus Create](#modus-create)
- [Licensing](#licensing)


# How it works

This project uses these tools and services:

* [Serverless framework](https://serverless.com/)
* [Auth0](https://auth0.com/), providing SAML & SSO Authentication via Google G-Suite or Github
* [Amazon API Gateway](https://aws.amazon.com/api-gateway/)
* [AWS Lambda](https://aws.amazon.com/lambda/) with [Node.js](https://nodejs.org/)
* [Amazon S3](https://aws.amazon.com/s3/) [Static Web Site Hosting](https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html)
* [DynamoDB](https://aws.amazon.com/dynamodb/)
* [AWS EC2](https://aws.amazon.com/ec2/) including [VPC Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)

<img src="/images/Diagram.png" width="800">

The front-end web site is hosted on a S3 bucket. A basic demo can be accessed [here](http://acme-instant-tunnel.s3-website-us-east-1.amazonaws.com/)

</br>
<img src='/images/Homepage.png' width="400">

Users are authenticated and authorized through Auth0. You are able to configure different Identity Providers but Google G-Suite is the default.

<img src='/images/Auth0.png' width= "400">

Once logged in, users can click _Tunnel into EC2_ to gain access to an EC2 instance via SSH. </br>

<img src="/images/TunnelSuccess.png" width="400">

The code in this project uses the Serverless Framework to configure the underlying resources - AWS Lambda functions, DynamoDB table, and Security Groups.
When a user clicks _Tunnel into EC2_, it triggers a Lambda function that adds an entry to the preconfigured DynamoDB table and a temporary permission into the preconfigured Security Group that is connected to an EC2 instance.
<br/>

An item with lease start and end time, user IP address, and email address are added to DynamoDB table. The timestamps are in seconds since Epoch format. A corresponding security group ingress permission is added. The user can now SSH into this instance.
<img src="/images/Dynamo.png"> </br>
Security Group is added based on the IP Address & email held in the DynamoDB table.
</br>
<img src="/images/SGSuccess.png">


The DynamoDB table has TTL enabled on the leaseEnd attribute. When the leaseEnd attribute is expired, the item will automatically delete itself and will also revoke the corresponding security group ingress permission. The user now cannot SSH into this instance.

</br>
<img src="/images/SGRemoved.png">

# Getting Started

1. Make sure you have the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html) installed and that AWS credentials are properly configured before starting. You can do this by running `aws configure` on the command line.
2. Clone this repository, change directory to it, and run `npm install`
3. Go to [Auth0](https://auth0.com/) and sign up for an account. Go to Applications and click on your Default App. Here you can find your Auth0 development credentials for the next steps. Save the Client ID and Domain.
4. Copy `secrets.json.sample`, `serverless.yml.sample`,
   `public_key.sample` to new files without `.sample`
4. Edit the `secrets.json` file and replace `AUTH0_CLIENT_ID` with the Client ID found in the previous step.
5. Go back to Auth0 Application settings and click on _Show Advanced Settings -> Certificates_. Copy and paste the Signing Certificate into the `public_key` file.
6. Edit `frontend/app.js`. Replace `AUTH0_CLIENT_ID` with the Client ID and `AUTH0_DOMAIN` with the Domain found in Step 3. Replace `leaseTime` with the desired time for temporary SSH permissions in __seconds__
7. Edit the `serverless.yml` file where you will need to change the environment variables under _provider -> environment_ section.

- Change `VPC_ID` to your vpc id. You can find it in the AWS Console in the VPC section under Your VPCs.
- Change `USER_AWS_REGION` to the region you want to deploy resources in
- Change `S3_BUCKET_NAME` to something unique. An error will be thrown if the S3 bucket name is already taken.

8. Run `sls deploy` at the command line.
9. A URL will be generated under endpoints if deployment runs sucessfully. In `app.js`, replace `PRIVATE_ENDPOINT` with this URL. Run `sls client deploy` and type Y when prompted. This updates and deploys the front-end.
10. With a successful front-end deployment, you should get an S3 URL where the web app is hosted. Copy this URL and go to Auth0 settings. Find _Allowed Callback URIs_ under Application URIs and paste the S3 URL into this box. Make sure to Save Changes at the bottom.
11. Open the AWS Console and go to the EC2 instances section. Launch an EC2 instance (any storage or instance type settings are fine). Configure an existing security group and select the acme-instant-tunnel group that was generated during deployment. Generate and key pair and make sure to keep track of the key pair for when you want to SSH into the instance.
12. Navigate to the S3 URL that was generated in Steps 9-10. You should be able to log in and click Tunnel into EC2 with a success message 'You can now SSH into the EC2 instance for 1 hour'. After this, you can try to connect to the EC2 instance via SSH and it should work.

# Developing

A development environment can be set up by following the steps outlined in [Getting Started](#getting-started)

## Prerequisites

- [AWS Account](https://aws.amazon.com/)
- [Auth0 Account](https://auth0.com/)

## Testing

This project currently has no formal test suite of manual or automated tests. Deploy the code and perform manual exploratory tests. Contributions of tests would be welcome.

## Contributing

Check out the [contributing guide](/.github/CONTRIBUTING.md).

# References

* The classic Warner Brothers cartoon _Fast and Furry-ous_: [watch it on YouTube](https://www.youtube.com/watch?v=4iWvedIhWjM) and [learn about its history on Wikipedia](https://en.wikipedia.org/wiki/Fast_and_Furry-ous)
* Serverless Auth0 [tutorial](https://www.serverless.com/examples/aws-node-auth0-custom-authorizers-api)
# Modus Create

[Modus Create](https://moduscreate.com) is a digital product consultancy. We use a distributed team of the best talent in the world to offer a full suite of digital product design-build services; ranging from consumer facing apps, to digital migration, to agile development training, and business transformation.

<a href="https://moduscreate.com/?utm_source=labs&utm_medium=github&utm_campaign=PROJECT_NAME"><img src="https://res.cloudinary.com/modus-labs/image/upload/h_80/v1533109874/modus/logo-long-black.svg" height="80" alt="Modus Create"/></a>
<br />

This project is part of [Modus Labs](https://labs.moduscreate.com/?utm_source=labs&utm_medium=github&utm_campaign=PROJECT_NAME).

<a href="https://labs.moduscreate.com/?utm_source=labs&utm_medium=github&utm_campaign=PROJECT_NAME"><img src="https://res.cloudinary.com/modus-labs/image/upload/h_80/v1531492623/labs/logo-black.svg" height="80" alt="Modus Labs"/></a>

# Licensing

This project is [MIT licensed](./LICENSE).
