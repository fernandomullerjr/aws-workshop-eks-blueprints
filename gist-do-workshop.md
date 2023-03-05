# EKS Blueprints Workshop

This workshop helps you build a multi-team platform on top of EKS.

It will enable multiple development teams at your organization to deploy workloads freely without the platform team being the bottleneck. We walk through the baseline setup of an EKS cluster, and gradually add add-ons to easily enhance its capabilities such as enabling ArgoCD, Rollouts, GitOps and other common open-source add-ons.

**Event Engine Access:**

Event Hash:

Event Engine: https://dashboard.eventengine.run/

Workshop Link: https://catalog.workshops.aws/eks-blueprints-terraform/en-US

# Before start

Before start the workshop we need to setup some additional tooling in our Cloud9 Instance.

```bash
export INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
export CLOUD9_VOL_ID=$(aws ec2 describe-instances --instance-ids=$INSTANCE_ID --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs[].VolumeId' --output text)
aws ec2 modify-volume --volume-id=$CLOUD9_VOL_ID --size=30
aws s3 cp s3://ee-assets-prod-us-east-1/modules/3f05fe2b344a49cda0eb4c465c609b58/v3/eksinit.sh .
chmod 755 eksinit.sh
./eksinit.sh
source ~/.bashrc
aws cloud9 update-environment  --environment-id $C9_PID --managed-credentials-action DISABLE
sed -i '/aws cloud9 update-environment/d' /home/ec2-user/.bashrc
sudo shutdown -c; sudo shutdown -rf now
```
