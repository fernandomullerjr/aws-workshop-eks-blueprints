
Lucas Soriano
Rodrigo Bersa

git status
git add .
git commit -m "AWS Workshop"
eval $(ssh-agent -s)
ssh-add /home/fernando/.ssh/chave-debian10-github
git push
git status



https://github.com/aws/karpenter


https://gist.github.com/lusoal/789473387ea1ca20e40816590981adbc


https://catalog.workshops.aws/eks-blueprints-terraform/en-US



https://dashboard.eventengine.run/login

Enter your event hash
A 12 or 16 digit hash that was given to you for this event or for a specific team 

[March 2, 2023, 2:26 PM] Alves Duarte, Lucas Soriano: f652-1e2e523184-37

f652-1e2e523184-37










Abrir AWS Console
Cloud9

vai ter um ambiente



no EKS
vai ter um eks deployado via terraform
















https://catalog.workshops.aws/eks-blueprints-terraform/en-US/030-provision-eks-cluster/3-provision-cluster


- Verificando se tudo está igual


# then provision our EKS cluster
# the auto approve flag avoids you having to confirm you want to provision resources.
terraform apply -auto-approve




eks-blueprint  README.md
TeamRole:~/environment $ cd eks-blueprint/
TeamRole:~/environment/eks-blueprint $ ls
data.tf  locals.tf  main.tf  outputs.tf  providers.tf  terraform.tfstate
TeamRole:~/environment/eks-blueprint $ # then provision our EKS cluster
TeamRole:~/environment/eks-blueprint $ # the auto approve flag avoids you having to confirm you want to provision resources.
TeamRole:~/environment/eks-blueprint $ terraform apply -auto-approve
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
data.aws_region.current: Reading...
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...

No changes. Your infrastructure matches the configuration.

Terraform has compared your real infrastructure against your configuration and found no differences, so no changes are needed.

Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:

configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 

















https://catalog.workshops.aws/eks-blueprints-terraform/en-US/030-provision-eks-cluster/4-add-platform-and-dev-teams

Add Platform and Application Teams
Add Platform Team

The first thing we need to do, is add the Platform Team definition to our main.tf in the module eks_blueprints. This is the team that manages the EKS cluster provisioning.

Copy the platform team definition

  platform_teams = {
    admin = {
      users = [
        data.aws_caller_identity.current.arn
      ]
    }
  }



This will create a dedicated role arn:aws:iam::0123456789:role/eks-blueprint-admin-access that will allow you to managed the cluster as administrator.

It also define which existing users/roles will be allowed to assume this role via the users parameter where you can provide a list of IAM arns. The new role is also configured in the EKS Configmap to allow authentication.











## Add Riker Team EKS Tenant

Our next step is to define a Development Team in the EKS Platform as a Tenant. To do that, we add the following section to the main.tf

Under the platform team definition we add the following. If you have specific IAM Roles you would like to add to the team definition, you can do so in the users array which expects the IAM Role ARN.
Quotas are also enabled as shown below. Deploying resources without CPU or Memory limits will fail.


Add code below after the platform_teams we just added in eks_blueprints module

  application_teams = {
    team-riker = {
      "labels" = {
        "appName"     = "riker-team-app",
        "projectName" = "project-riker",
        "environment" = "dev",
        "domain"      = "example",
        "uuid"        = "example",
        "billingCode" = "example",
        "branch"      = "example"
      }
      "quota" = {
        "requests.cpu"    = "10",
        "requests.memory" = "20Gi",
        "limits.cpu"      = "30",
        "limits.memory"   = "50Gi",
        "pods"            = "15",
        "secrets"         = "10",
        "services"        = "10"
      }
      ## Manifests Example: we can specify a directory with kubernetes manifests that can be automatically applied in the team-riker namespace.
      manifests_dir = "./kubernetes/team-riker"
      users         = [data.aws_caller_identity.current.arn]
    }
  }

This will create a dedicated role arn:aws:iam::0123456789:role/eks-blueprint-team-riker-access that will allow you to managed the Team Riker authentication in EKS. The created IAM role will also be configured in the EKS Configmap.

The Team Riker being created is in fact a Kubernetes namespace with associated kubernetes RBAC and quotas, in this case team-riker. You can adjust the labels and quotas to values appropriate to the team you are adding. EKS

We are also using the manifest_dir directory that allow you to install specific kubernetes manifests at the namespace creation time. You can bootstrap the namespace with dedicated network policies rules, or anything that you need.

    Blueprint chooses to use namespaces and resource quotas to isolate application teams from each others. We can also add additional security policy enforcements and Network segreagation by applying additional kubernetes manifests when creating the teams namespaces.






We are going to create a default limit range that will inject default resources/limits to our pods if they where not defined

mkdir -p kubernetes/team-riker
cat << EOF > kubernetes/team-riker/limit-range.yaml
apiVersion: 'v1'
kind: 'LimitRange'
metadata:
  name: 'resource-limits'
  namespace: team-riker
spec:
  limits:
    - type: 'Container'
      max:
        cpu: '2'
        memory: '1Gi'
      min:
        cpu: '50m'
        memory: '4Mi'
      default:
        cpu: '300m'
        memory: '200Mi'
      defaultRequest:
        cpu: '200m'
        memory: '100Mi'
      maxLimitRequestRatio:
        cpu: '10'
EOF





TeamRole:~/environment/eks-blueprint $ mkdir -p kubernetes/team-riker
TeamRole:~/environment/eks-blueprint $ cat << EOF > kubernetes/team-riker/limit-range.yaml
> apiVersion: 'v1'
> kind: 'LimitRange'
> metadata:
>   name: 'resource-limits'
>   namespace: team-riker
> spec:
>   limits:
>     - type: 'Container'
>       max:
>         cpu: '2'
>         memory: '1Gi'
>       min:
>         cpu: '50m'
>         memory: '4Mi'
>       default:
>         cpu: '300m'
>         memory: '200Mi'
>       defaultRequest:
>         cpu: '200m'
>         memory: '100Mi'
>       maxLimitRequestRatio:
>         cpu: '10'
> EOF
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 


Important
Don't forget to save the cloud9 file as auto-save is not enabled by default.

Now using the Terraform CLI, update the resources in AWS using the cli, note the -auto-approve flag that skips user approval to deploy changes without having to type “yes” as a confirmation to provision resources.

1
2
# Always a good practice to use a dry-run command
terraform plan

1
2
# apply changes to provision the Platform Team
terraform apply -auto-approve


- Efetuando plan:

~~~~bash
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform plan
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
data.aws_caller_identity.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_availability_zones.available: Reading...
data.aws_region.current: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_availability_zones.available: Read complete after 0s [id=us-east-1]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster_auth.this: Reading...
data.aws_eks_cluster.cluster: Reading...
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
  ~ update in-place
 <= read (data resources)

Terraform will perform the following actions:

  # module.eks_blueprints.kubernetes_config_map.aws_auth[0] will be updated in-place
  ~ resource "kubernetes_config_map" "aws_auth" {
      ~ data        = {
          ~ "mapRoles"    = <<-EOT
                - "groups":
                  - "system:bootstrappers"
                  - "system:nodes"
                  "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-managed-ondemand"
                  "username": "system:node:{{EC2PrivateDNSName}}"
                - "groups":
              +   - "team-riker-group"
              +   "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
              +   "username": "team-riker"
              + - "groups":
                  - "system:masters"
              +   "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
              +   "username": "admin"
              + - "groups":
              +   - "system:masters"
                  "rolearn": "arn:aws:iam::537174683150:role/TeamRole"
                  "username": "ops-role"
            EOT
            # (2 unchanged elements hidden)
        }
        id          = "kube-system/aws-auth"
        # (2 unchanged attributes hidden)

        # (1 unchanged block hidden)
    }

  # module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy will be read during apply
  # (depends on a resource or a module with changes pending)
 <= data "aws_iam_policy_document" "managed_ng_assume_role_policy" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRole",
            ]
          + sid     = "EKSWorkerAssumeRole"

          + principals {
              + identifiers = [
                  + "ec2.amazonaws.com",
                ]
              + type        = "Service"
            }
        }
    }

  # module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0] will be updated in-place
  ~ resource "aws_iam_role" "managed_ng" {
      ~ assume_role_policy    = jsonencode(
            {
              - Statement = [
                  - {
                      - Action    = "sts:AssumeRole"
                      - Effect    = "Allow"
                      - Principal = {
                          - Service = "ec2.amazonaws.com"
                        }
                      - Sid       = "EKSWorkerAssumeRole"
                    },
                ]
              - Version   = "2012-10-17"
            }
        ) -> (known after apply)
        id                    = "eks-blueprint-managed-ondemand"
        name                  = "eks-blueprint-managed-ondemand"
        tags                  = {
            "Blueprint"  = "eks-blueprint"
            "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
        # (9 unchanged attributes hidden)
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0] will be created
  + resource "aws_iam_policy" "platform_team_eks_access" {
      + arn         = (known after apply)
      + description = "Platform Team EKS Console Access"
      + id          = (known after apply)
      + name        = "eks-blueprint-PlatformTeamEKSAccess"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ssm:GetParameter",
                          + "eks:ListUpdates",
                          + "eks:ListNodegroups",
                          + "eks:ListFargateProfiles",
                          + "eks:ListClusters",
                          + "eks:DescribeNodegroup",
                          + "eks:DescribeCluster",
                          + "eks:AccessKubernetesApi",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:eks:us-east-1:537174683150:cluster/eks-blueprint"
                      + Sid      = "AllowPlatformTeamEKSAccess"
                    },
                  + {
                      + Action   = "eks:ListClusters"
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "AllowListClusters"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags        = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all    = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"] will be created
  + resource "aws_iam_role" "platform_team" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + AWS = [
                              + "arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba",
                            ]
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "eks-blueprint-admin-access"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"] will be created
  + resource "aws_iam_role" "team_access" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + AWS = [
                              + "arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba",
                            ]
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "eks-blueprint-team-riker-access"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"] will be created
  + resource "aws_iam_role" "team_sa_irsa" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRoleWithWebIdentity"
                      + Condition = {
                          + StringEquals = {
                              + "oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672:aud" = "sts.amazonaws.com"
                              + "oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672:sub" = "system:serviceaccount:team-riker:team-riker-sa"
                            }
                        }
                      + Effect    = "Allow"
                      + Principal = {
                          + Federated = "arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "eks-blueprint-team-riker-sa-role"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"] will be created
  + resource "kubectl_manifest" "team" {
      + api_version             = "v1"
      + apply_only              = false
      + force_conflicts         = false
      + force_new               = false
      + id                      = (known after apply)
      + kind                    = "LimitRange"
      + live_manifest_incluster = (sensitive value)
      + live_uid                = (known after apply)
      + name                    = "resource-limits"
      + namespace               = "team-riker"
      + server_side_apply       = false
      + uid                     = (known after apply)
      + validate_schema         = true
      + wait_for_rollout        = true
      + yaml_body               = (sensitive value)
      + yaml_body_parsed        = <<-EOT
            apiVersion: v1
            kind: LimitRange
            metadata:
              name: resource-limits
              namespace: team-riker
            spec:
              limits:
              - default:
                  cpu: 300m
                  memory: 200Mi
                defaultRequest:
                  cpu: 200m
                  memory: 100Mi
                max:
                  cpu: "2"
                  memory: 1Gi
                maxLimitRequestRatio:
                  cpu: "10"
                min:
                  cpu: 50m
                  memory: 4Mi
                type: Container
        EOT
      + yaml_incluster          = (sensitive value)
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"] will be created
  + resource "kubernetes_cluster_role" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-team-cluster-role"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + rule {
          + api_groups = [
              + "",
            ]
          + resources  = [
              + "namespaces",
              + "nodes",
            ]
          + verbs      = [
              + "get",
              + "list",
              + "watch",
            ]
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"] will be created
  + resource "kubernetes_cluster_role_binding" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-team-cluster-role-binding"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + role_ref {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "ClusterRole"
          + name      = "team-riker-team-cluster-role"
        }

      + subject {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "Group"
          + name      = "team-riker-group"
          + namespace = "default"
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"] will be created
  + resource "kubernetes_namespace" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + labels           = {
              + "appName"     = "riker-team-app"
              + "billingCode" = "example"
              + "branch"      = "example"
              + "domain"      = "example"
              + "environment" = "dev"
              + "projectName" = "project-riker"
              + "uuid"        = "example"
            }
          + name             = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"] will be created
  + resource "kubernetes_resource_quota" "this" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "quotas"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + spec {
          + hard = {
              + "limits.cpu"      = "30"
              + "limits.memory"   = "50Gi"
              + "pods"            = "15"
              + "requests.cpu"    = "10"
              + "requests.memory" = "20Gi"
              + "secrets"         = "10"
              + "services"        = "10"
            }
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"] will be created
  + resource "kubernetes_role" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-role"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + rule {
          + api_groups = [
              + "*",
            ]
          + resources  = [
              + "configmaps",
              + "deployments",
              + "horizontalpodautoscalers",
              + "networkpolicies",
              + "pods",
              + "podtemplates",
              + "replicasets",
              + "secrets",
              + "serviceaccounts",
              + "services",
              + "statefulsets",
            ]
          + verbs      = [
              + "get",
              + "list",
              + "watch",
            ]
        }
      + rule {
          + api_groups = [
              + "*",
            ]
          + resources  = [
              + "resourcequotas",
            ]
          + verbs      = [
              + "get",
              + "list",
              + "watch",
            ]
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"] will be created
  + resource "kubernetes_role_binding" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-role-binding"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + role_ref {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "Role"
          + name      = "team-riker-role"
        }

      + subject {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "Group"
          + name      = "team-riker-group"
          + namespace = "team-riker"
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"] will be created
  + resource "kubernetes_service_account" "team" {
      + automount_service_account_token = true
      + default_secret_name             = (known after apply)
      + id                              = (known after apply)

      + metadata {
          + annotations      = (known after apply)
          + generation       = (known after apply)
          + name             = "team-riker-sa"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

Plan: 12 to add, 2 to change, 0 to destroy.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't guarantee to take exactly these actions if you run "terraform apply" now.
TeamRole:~/environment/eks-blueprint $ 
~~~~




- Aplicando:


~~~~bash
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform apply -auto-approve
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_region.current: Reading...
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
data.aws_availability_zones.available: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
data.aws_region.current: Reading...
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_availability_zones.available: Read complete after 1s [id=us-east-1]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 1s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
data.aws_eks_cluster_auth.this: Reading...
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
data.aws_eks_cluster.cluster: Reading...
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
  ~ update in-place
 <= read (data resources)

Terraform will perform the following actions:

  # module.eks_blueprints.kubernetes_config_map.aws_auth[0] will be updated in-place
  ~ resource "kubernetes_config_map" "aws_auth" {
      ~ data        = {
          ~ "mapRoles"    = <<-EOT
                - "groups":
                  - "system:bootstrappers"
                  - "system:nodes"
                  "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-managed-ondemand"
                  "username": "system:node:{{EC2PrivateDNSName}}"
                - "groups":
              +   - "team-riker-group"
              +   "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
              +   "username": "team-riker"
              + - "groups":
                  - "system:masters"
              +   "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
              +   "username": "admin"
              + - "groups":
              +   - "system:masters"
                  "rolearn": "arn:aws:iam::537174683150:role/TeamRole"
                  "username": "ops-role"
            EOT
            # (2 unchanged elements hidden)
        }
        id          = "kube-system/aws-auth"
        # (2 unchanged attributes hidden)

        # (1 unchanged block hidden)
    }

  # module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy will be read during apply
  # (depends on a resource or a module with changes pending)
 <= data "aws_iam_policy_document" "managed_ng_assume_role_policy" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRole",
            ]
          + sid     = "EKSWorkerAssumeRole"

          + principals {
              + identifiers = [
                  + "ec2.amazonaws.com",
                ]
              + type        = "Service"
            }
        }
    }

  # module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0] will be updated in-place
  ~ resource "aws_iam_role" "managed_ng" {
      ~ assume_role_policy    = jsonencode(
            {
              - Statement = [
                  - {
                      - Action    = "sts:AssumeRole"
                      - Effect    = "Allow"
                      - Principal = {
                          - Service = "ec2.amazonaws.com"
                        }
                      - Sid       = "EKSWorkerAssumeRole"
                    },
                ]
              - Version   = "2012-10-17"
            }
        ) -> (known after apply)
        id                    = "eks-blueprint-managed-ondemand"
        name                  = "eks-blueprint-managed-ondemand"
        tags                  = {
            "Blueprint"  = "eks-blueprint"
            "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
        # (9 unchanged attributes hidden)
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0] will be created
  + resource "aws_iam_policy" "platform_team_eks_access" {
      + arn         = (known after apply)
      + description = "Platform Team EKS Console Access"
      + id          = (known after apply)
      + name        = "eks-blueprint-PlatformTeamEKSAccess"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ssm:GetParameter",
                          + "eks:ListUpdates",
                          + "eks:ListNodegroups",
                          + "eks:ListFargateProfiles",
                          + "eks:ListClusters",
                          + "eks:DescribeNodegroup",
                          + "eks:DescribeCluster",
                          + "eks:AccessKubernetesApi",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:eks:us-east-1:537174683150:cluster/eks-blueprint"
                      + Sid      = "AllowPlatformTeamEKSAccess"
                    },
                  + {
                      + Action   = "eks:ListClusters"
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "AllowListClusters"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags        = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all    = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"] will be created
  + resource "aws_iam_role" "platform_team" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + AWS = [
                              + "arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba",
                            ]
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "eks-blueprint-admin-access"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"] will be created
  + resource "aws_iam_role" "team_access" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + AWS = [
                              + "arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba",
                            ]
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "eks-blueprint-team-riker-access"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"] will be created
  + resource "aws_iam_role" "team_sa_irsa" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRoleWithWebIdentity"
                      + Condition = {
                          + StringEquals = {
                              + "oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672:aud" = "sts.amazonaws.com"
                              + "oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672:sub" = "system:serviceaccount:team-riker:team-riker-sa"
                            }
                        }
                      + Effect    = "Allow"
                      + Principal = {
                          + Federated = "arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "eks-blueprint-team-riker-sa-role"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"] will be created
  + resource "kubectl_manifest" "team" {
      + api_version             = "v1"
      + apply_only              = false
      + force_conflicts         = false
      + force_new               = false
      + id                      = (known after apply)
      + kind                    = "LimitRange"
      + live_manifest_incluster = (sensitive value)
      + live_uid                = (known after apply)
      + name                    = "resource-limits"
      + namespace               = "team-riker"
      + server_side_apply       = false
      + uid                     = (known after apply)
      + validate_schema         = true
      + wait_for_rollout        = true
      + yaml_body               = (sensitive value)
      + yaml_body_parsed        = <<-EOT
            apiVersion: v1
            kind: LimitRange
            metadata:
              name: resource-limits
              namespace: team-riker
            spec:
              limits:
              - default:
                  cpu: 300m
                  memory: 200Mi
                defaultRequest:
                  cpu: 200m
                  memory: 100Mi
                max:
                  cpu: "2"
                  memory: 1Gi
                maxLimitRequestRatio:
                  cpu: "10"
                min:
                  cpu: 50m
                  memory: 4Mi
                type: Container
        EOT
      + yaml_incluster          = (sensitive value)
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"] will be created
  + resource "kubernetes_cluster_role" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-team-cluster-role"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + rule {
          + api_groups = [
              + "",
            ]
          + resources  = [
              + "namespaces",
              + "nodes",
            ]
          + verbs      = [
              + "get",
              + "list",
              + "watch",
            ]
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"] will be created
  + resource "kubernetes_cluster_role_binding" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-team-cluster-role-binding"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + role_ref {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "ClusterRole"
          + name      = "team-riker-team-cluster-role"
        }

      + subject {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "Group"
          + name      = "team-riker-group"
          + namespace = "default"
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"] will be created
  + resource "kubernetes_namespace" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + labels           = {
              + "appName"     = "riker-team-app"
              + "billingCode" = "example"
              + "branch"      = "example"
              + "domain"      = "example"
              + "environment" = "dev"
              + "projectName" = "project-riker"
              + "uuid"        = "example"
            }
          + name             = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"] will be created
  + resource "kubernetes_resource_quota" "this" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "quotas"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + spec {
          + hard = {
              + "limits.cpu"      = "30"
              + "limits.memory"   = "50Gi"
              + "pods"            = "15"
              + "requests.cpu"    = "10"
              + "requests.memory" = "20Gi"
              + "secrets"         = "10"
              + "services"        = "10"
            }
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"] will be created
  + resource "kubernetes_role" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-role"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + rule {
          + api_groups = [
              + "*",
            ]
          + resources  = [
              + "configmaps",
              + "deployments",
              + "horizontalpodautoscalers",
              + "networkpolicies",
              + "pods",
              + "podtemplates",
              + "replicasets",
              + "secrets",
              + "serviceaccounts",
              + "services",
              + "statefulsets",
            ]
          + verbs      = [
              + "get",
              + "list",
              + "watch",
            ]
        }
      + rule {
          + api_groups = [
              + "*",
            ]
          + resources  = [
              + "resourcequotas",
            ]
          + verbs      = [
              + "get",
              + "list",
              + "watch",
            ]
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"] will be created
  + resource "kubernetes_role_binding" "team" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "team-riker-role-binding"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + role_ref {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "Role"
          + name      = "team-riker-role"
        }

      + subject {
          + api_group = "rbac.authorization.k8s.io"
          + kind      = "Group"
          + name      = "team-riker-group"
          + namespace = "team-riker"
        }
    }

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"] will be created
  + resource "kubernetes_service_account" "team" {
      + automount_service_account_token = true
      + default_secret_name             = (known after apply)
      + id                              = (known after apply)

      + metadata {
          + annotations      = (known after apply)
          + generation       = (known after apply)
          + name             = "team-riker-sa"
          + namespace        = "team-riker"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

Plan: 12 to add, 2 to change, 0 to destroy.
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Creation complete after 0s [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Creation complete after 0s [id=eks-blueprint-team-riker-access]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Modifying... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Creation complete after 0s [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Creation complete after 0s [id=team-riker-team-cluster-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Creation complete after 0s [id=team-riker]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Creation complete after 0s [id=eks-blueprint-team-riker-sa-role]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Modifications complete after 0s [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Creating...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Creation complete after 0s [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Creation complete after 1s [id=team-riker/team-riker-role]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Creation complete after 1s [id=eks-blueprint-admin-access]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Creation complete after 1s [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Creation complete after 1s [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Creation complete after 1s [id=team-riker/team-riker-sa]

Apply complete! Resources: 12 added, 1 changed, 0 destroyed.

Outputs:

configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 

~~~~
















There are several resources created when you onboard a team. including a Kubernetes Service Account created for the team. To view a full list, you can execute terraform state list and you should see resources similar to the ones shown below

terraform state list module.eks_blueprints.module.aws_eks_teams

~~~~bash
# ommited lines for brevity

...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.team_compute_quota["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.team_object_quota["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]

~~~~



TeamRole:~/environment/eks-blueprint $ terraform state list module.eks_blueprints.module.aws_eks_teams
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]
TeamRole:~/environment/eks-blueprint $ 

















You can see in more detailed in the terraform state what AWS resources were created with our team module. For example you can see the platform team details:

terraform state show 'module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]'

~~~~bash
# module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]:
resource "aws_iam_role" "platform_team" {
    arn                   = "arn:aws:iam::0123456789:role/eks-blueprint-admin-access"
    assume_role_policy    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRole"
                    Effect    = "Allow"
                    Principal = {
                        AWS = [
                            "arn:aws:sts::0123456789:assumed-role/eks-blueprints-for-terraform-workshop-admin/i-09e1d15b60696663c",
                            "arn:aws:iam::0123456789:role/TeamRole",
                        ]
                    }
                },
            ]
            Version   = "2012-10-17"
        }
    )
    create_date           = "2022-06-15T08:39:04Z"
    force_detach_policies = false
    id                    = "eks-blueprint-admin-access"
    managed_policy_arns   = [
        "arn:aws:iam::0123456789:policy/eks-blueprint-PlatformTeamEKSAccess",
    ]
    max_session_duration  = 3600
    name                  = "eks-blueprint-admin-access"
    path                  = "/"
    tags                  = {
        "Blueprint"  = "eks-blueprint"
        "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
    }
    tags_all              = {
        "Blueprint"  = "eks-blueprint"
        "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
    }
    unique_id             = "AROA6NAAL5J5PF2ZPWHJP"

    inline_policy {}
}
~~~~






~~~~bash

TeamRole:~/environment/eks-blueprint $ terraform state show 'module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]'
# module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]:
resource "aws_iam_role" "platform_team" {
    arn                   = "arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
    assume_role_policy    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRole"
                    Effect    = "Allow"
                    Principal = {
                        AWS = [
                            "arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba",
                        ]
                    }
                },
            ]
            Version   = "2012-10-17"
        }
    )
    create_date           = "2023-03-02T17:59:20Z"
    force_detach_policies = false
    id                    = "eks-blueprint-admin-access"
    managed_policy_arns   = [
        "arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess",
    ]
    max_session_duration  = 3600
    name                  = "eks-blueprint-admin-access"
    path                  = "/"
    tags                  = {
        "Blueprint"  = "eks-blueprint"
        "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
    }
    tags_all              = {
        "Blueprint"  = "eks-blueprint"
        "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
    }
    unique_id             = "AROAX2EQ3FYHMTJ3WSOSA"
}
TeamRole:~/environment/eks-blueprint $ 
~~~~


Let's see how we can leverage the roles associated with our created Teams, in the next section.

































Connect to EKS Created Cluster

In the previous step, we created the EKS cluster, and the module outputs the kubeconfig information which we can use to connect to the cluster.
Step 1: Configure KubeConfig

The output configure_kubectl contains the command you can execute in your terminal to connect to the newly created cluster, example:

1
terraform output

configure_kubectl = "aws eks --region us-east-2 update-kubeconfig --name eks-blueprint"





TeamRole:~/environment/eks-blueprint $ terraform output
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 






Important
Copy the command from your own terraform output not the example above. The region value might be different.: aws eks --region <YOUR_REGION> update-kubeconfig --name eks-blueprint

Let's see that kubectl is properly configured

1
kubectl get nodes



TeamRole:~/environment/eks-blueprint $ aws eks --region us-east-1 update-kubeconfig --name eks-blueprint
Updated context arn:aws:eks:us-east-1:537174683150:cluster/eks-blueprint in /home/ec2-user/.kube/config
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get nodes
NAME                          STATUS   ROLES    AGE     VERSION
ip-10-0-10-26.ec2.internal    Ready    <none>   3h24m   v1.23.16-eks-48e63af
ip-10-0-11-201.ec2.internal   Ready    <none>   3h24m   v1.23.16-eks-48e63af
ip-10-0-12-133.ec2.internal   Ready    <none>   3h24m   v1.23.16-eks-48e63af
TeamRole:~/environment/eks-blueprint $ 














Now we are connected on EKS with the super admin role which is our current role, the one that was used to create the cluster.

We can see the EKS auth configmap in order to see which roles are allowed to connect

1
kubectl get configmap -n kube-system aws-auth -o yaml



TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get configmap -n kube-system aws-auth -o yaml
apiVersion: v1
data:
  mapAccounts: |
    []
  mapRoles: |
    - "groups":
      - "system:bootstrappers"
      - "system:nodes"
      "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-managed-ondemand"
      "username": "system:node:{{EC2PrivateDNSName}}"
    - "groups":
      - "team-riker-group"
      "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
      "username": "team-riker"
    - "groups":
      - "system:masters"
      "rolearn": "arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
      "username": "admin"
    - "groups":
      - "system:masters"
      "rolearn": "arn:aws:iam::537174683150:role/TeamRole"
      "username": "ops-role"
  mapUsers: |
    []
immutable: false
kind: ConfigMap
metadata:
  creationTimestamp: "2023-03-02T14:45:48Z"
  labels:
    app.kubernetes.io/created-by: terraform-aws-eks-blueprints
    app.kubernetes.io/managed-by: terraform-aws-eks-blueprints
  name: aws-auth
  namespace: kube-system
  resourceVersion: "33490"
  uid: 63194857-3758-463c-b8f9-f4d4a693218e
TeamRole:~/environment/eks-blueprint $ 


















Step 2: Connect to cluster as Team Riker

At the time we created the EKS cluster, the current identity was automatically added to the Application team-riker Team thanks to the users parameter.

If you added additional IAM Role ARNs during the definition of Team-Riker, then you can safely assume that role as it was added to the auth configmap of the cluster.

If you want to get the command to configure kubectl for each team, you can add to the output to retrieve them.

Add those 2 outputs in output.tf

1
2
3
4
5
6
7
8
9
output "platform_teams_configure_kubectl" {
  description = "Configure kubectl for each Platform Team: make sure you're logged in with the correct AWS CLI profile and run the following command to update your kubeconfig"
  value       = try(module.eks_blueprints.teams[0].platform_teams_configure_kubectl["admin"], null)
}

output "application_teams_configure_kubectl" {
  description = "Configure kubectl for each Application Teams: make sure you're logged in with the correct AWS CLI profile and run the following command to update your kubeconfig"
  value       = try(module.eks_blueprints.teams[0].application_teams_configure_kubectl["team-riker"], null)
}





















Important
Don't forget to save the cloud9 file as auto-save is not enabled by default.

Now redeploy with the new outputs

1
2
# Always a good practice to use a dry-run command
terraform plan

1
2
# apply changes to provision the Platform Team
terraform apply -auto-approve

You will see the kubectl configuration command to share with members of Team Riker, copy the aws eks update-kubeconfig ... command portion of the output and run the command.

application_teams_configure_kubectl = "aws eks --region us-east-2 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::0123456789:role/eks-blueprint-team-riker-access"

Important
Copy the command from your own terraform output not the example above. The region and account id values might be different.




TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform plan
data.aws_availability_zones.available: Reading...
data.aws_caller_identity.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.eks_blueprints.data.aws_caller_identity.current: Reading...
data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_region.current: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_availability_zones.available: Read complete after 0s [id=us-east-1]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 1s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
data.aws_eks_cluster.cluster: Reading...
data.aws_eks_cluster_auth.this: Reading...
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-access]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Refreshing state... [id=team-riker]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-sa-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Refreshing state... [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Refreshing state... [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]

Changes to Outputs:
  + application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
  + platform_teams_configure_kubectl    = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"

You can apply this plan to save these new output values to the Terraform state, without changing any real infrastructure.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't guarantee to take exactly these actions if you run "terraform apply" now.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform apply -auto-approve
data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
data.aws_availability_zones.available: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.eks_blueprints.data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
data.aws_region.current: Reading...
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
data.aws_availability_zones.available: Read complete after 0s [id=us-east-1]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
data.aws_eks_cluster_auth.this: Reading...
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster.cluster: Reading...
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Refreshing state... [id=team-riker]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-access]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Refreshing state... [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Refreshing state... [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-sa-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]

Changes to Outputs:
  + application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
  + platform_teams_configure_kubectl    = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"

You can apply this plan to save these new output values to the Terraform state, without changing any real infrastructure.

Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 








application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"

aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access


TeamRole:~/environment/eks-blueprint $ aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access
Updated context arn:aws:eks:us-east-1:537174683150:cluster/eks-blueprint in /home/ec2-user/.kube/config
TeamRole:~/environment/eks-blueprint $ 
























ortant
Copy the command from your own terraform output not the example above. The region and account id values might be different.

Now you can execute kubectl CLI commands in the team-riker namespace.

Let's see if we can do same commands as previously ?

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
# list nodes ?
kubectl get nodes
# List pods in team-riker namespace ?
kubectl get pods -n team-riker
# list all pods in all namespaces ?
kubectl get pods -A
# can i create pods in kube-system namespace ?
kubectl auth can-i create pods --namespace kube-system
# list service accounts in team-riker namespace ?
kubectl get sa -n team-riker
# list service accounts in default namespace ?
kubectl get sa -n default
# can i create pods in team-riker namespace ?
kubectl auth can-i create pods --namespace team-riker
# can i list pods in team-riker namespace ?
kubectl auth can-i list pods --namespace team-riker



TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get nodes
NAME                          STATUS   ROLES    AGE     VERSION
ip-10-0-10-26.ec2.internal    Ready    <none>   3h30m   v1.23.16-eks-48e63af
ip-10-0-11-201.ec2.internal   Ready    <none>   3h30m   v1.23.16-eks-48e63af
ip-10-0-12-133.ec2.internal   Ready    <none>   3h30m   v1.23.16-eks-48e63af
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get pods -n team-riker
No resources found in team-riker namespace.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get pods -A
Error from server (Forbidden): pods is forbidden: User "team-riker" cannot list resource "pods" in API group "" at the cluster scope
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl auth can-i create pods --namespace kube-system
no
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get sa -n team-riker
NAME            SECRETS   AGE
default         1         19m
team-riker-sa   1         19m
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get sa -n default
Error from server (Forbidden): serviceaccounts is forbidden: User "team-riker" cannot list resource "serviceaccounts" in API group "" in the namespace "default"
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl auth can-i create pods --namespace team-riker
no
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl auth can-i list pods --namespace team-riker
yes
TeamRole:~/environment/eks-blueprint $ 






















You can see here that our team-riker role, has read only rights in the cluster, but only in the team-riker namespace.

You can always see the quotas of your namespace with

1
kubectl get resourcequotas -n team-riker

NAME     AGE   REQUEST                                                                                  LIMIT
quotas   83m   pods: 0/10, requests.cpu: 0/10, requests.memory: 0/20Gi, secrets: 2/10, services: 0/10   limits.cpu: 0/20, limits.memory: 0/50Gi

It is best practice to not create kubernetes objects with kubectl directly but to rely on continuous deployment tools, we are going to see in our next exercise how we can leverage ArgoCD for that purpose!



TeamRole:~/environment/eks-blueprint $ kubectl get resourcequotas -n team-riker
NAME     AGE   REQUEST                                                                                  LIMIT
quotas   20m   pods: 0/15, requests.cpu: 0/10, requests.memory: 0/20Gi, secrets: 2/10, services: 0/10   limits.cpu: 0/30, limits.memory: 0/50Gi
TeamRole:~/environment/eks-blueprint $ 















Connect to cluster as Platform Admin

At the time we created the EKS cluster, the current identity was automatically added to the Platform Team as shown below.

1
2
3
4
5
  platform_teams = {
    admin = {
      users = [data.aws_caller_identity.current.arn]
    }
  }

Assuming you added additional IAM Role Arns, these would also have administrative access to the cluster, therefore you can assume said roles.

On the output you also see the kubectl to share with members of Platform Admin team, copy the aws eks update-kubeconfig ... command portion of the output and run the command.

platform_teams_configure_kubectl = "aws eks --region us-west-2 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::0123456789:role/eks-blueprint-admin-access"

Important
Copy the command from your own terraform output not the example above. The region and account id values might be different.



platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access


Now, let's check what we can do on the EKS cluster:

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
# list nodes ?
kubectl get nodes
# List pods in team-riker namespace ?
kubectl get pods -n team-riker
# list all pods in all namespaces ?
kubectl get pods -A
# can i create pods in kube-system namespace ?
kubectl auth can-i create pods --namespace kube-system
# list service accounts in team-riker namespace ?
kubectl get sa -n team-riker
# list service accounts in default namespace ?
kubectl get sa -n default
# can i create pods in team-riker namespace ?
kubectl auth can-i create pods --namespace team-riker
# can i list pods in team-riker namespace ?
kubectl auth can-i list pods --namespace team-riker

This time there was no errors as we are using admin rights into our eks cluster.



TeamRole:~/environment/eks-blueprint $ aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access
Updated context arn:aws:eks:us-east-1:537174683150:cluster/eks-blueprint in /home/ec2-user/.kube/config
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get nodes
NAME                          STATUS   ROLES    AGE     VERSION
ip-10-0-10-26.ec2.internal    Ready    <none>   3h33m   v1.23.16-eks-48e63af
ip-10-0-11-201.ec2.internal   Ready    <none>   3h33m   v1.23.16-eks-48e63af
ip-10-0-12-133.ec2.internal   Ready    <none>   3h33m   v1.23.16-eks-48e63af
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get pods -n team-riker
No resources found in team-riker namespace.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get pods -A
NAMESPACE     NAME                     READY   STATUS    RESTARTS   AGE
kube-system   aws-node-9zzrf           1/1     Running   0          3h34m
kube-system   aws-node-c86b5           1/1     Running   0          3h34m
kube-system   aws-node-vkk6l           1/1     Running   0          3h33m
kube-system   coredns-d5b9bfc4-27rzs   1/1     Running   0          3h39m
kube-system   coredns-d5b9bfc4-mfxqp   1/1     Running   0          3h39m
kube-system   kube-proxy-bzhvv         1/1     Running   0          3h34m
kube-system   kube-proxy-n5v4l         1/1     Running   0          3h34m
kube-system   kube-proxy-sm9kw         1/1     Running   0          3h33m
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl auth can-i create pods --namespace kube-system
yes
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get sa -n team-riker
NAME            SECRETS   AGE
default         1         22m
team-riker-sa   1         22m
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get sa -n default
NAME      SECRETS   AGE
default   1         3h39m
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl auth can-i create pods --namespace team-riker
yes
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl auth can-i list pods --namespace team-riker
yes
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 













OK, Now configure kubectl back to the current creator of the EKS cluster.

configure_kubectl = "aws eks --region us-east-2 update-kubeconfig --name eks-blueprint"
aws eks --region us-east-2 update-kubeconfig --name eks-blueprint

Important
Copy the command from your own terraform output not the example above. The region value might be different.

In the next section we are going to Bootstrap a GitOps 
tools named ArgoCD 

that we will uses to managed add-ons and workloads deployment inside our EKS cluster.
[Optional] Assume the Platform Admin Role in the AWS Console



TeamRole:~/environment/eks-blueprint $ aws eks --region us-east-2 update-kubeconfig --name eks-blueprint

An error occurred (ResourceNotFoundException) when calling the DescribeCluster operation: No cluster found for name: eks-blueprint.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ aws eks --region us-east-1 update-kubeconfig --name eks-blueprint
Updated context arn:aws:eks:us-east-1:537174683150:cluster/eks-blueprint in /home/ec2-user/.kube/config
TeamRole:~/environment/eks-blueprint $ 

aws eks --region us-east-1 update-kubeconfig --name eks-blueprint
















----------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------
# Working with GitOps: Bootstrap ArgoCD

- Vão ser apontados para 2 repositórios
    The https://github.com/aws-samples/eks-blueprints-add-ons.git 
    is used to install add-ons. You don't need to fork it for this workshop
    The https://github.com/aws-samples/eks-blueprints-workloads.git 
    is used for deploying applications and you need to fork it.


- Forkear este:
https://github.com/aws-samples/eks-blueprints-workloads


- Forkeado:
https://github.com/fernandomullerjr/eks-blueprints-workloads








Add argo application config for both repositories, eks add-on and your forked of workload repositoryHeader anchor link

The first thing we need to do, is augment our locals.tf with the two new variables addon_application and workload_application as shown below.

Replace the entire contents of the locals.tf with the code below.

Update the repo_url for both the workload repository with your fork replacing [ YOUR GITHUB USER HERE ].


~~~~h
locals {
  name            = basename(path.cwd)
  region          = data.aws_region.current.name
  cluster_version = "1.23"

  vpc_cidr      = "10.0.0.0/16"
  azs           = slice(data.aws_availability_zones.available.names, 0, 3)

  node_group_name = "managed-ondemand"
  env = "dev"

  #---------------------------------------------------------------
  # ARGOCD ADD-ON APPLICATION
  #---------------------------------------------------------------

  addon_application = {
    path               = "chart"
    repo_url           = "https://github.com/aws-samples/eks-blueprints-add-ons.git"
    add_on_application = true
  }

  #---------------------------------------------------------------
  # ARGOCD WORKLOAD APPLICATION
  #---------------------------------------------------------------
  workload_repo = "https://github.com/[ YOUR GITHUB USER HERE ]/eks-blueprints-workloads.git"

  workload_application = {
    path               = "envs/dev"
    repo_url           = local.workload_repo
    add_on_application = false
    values = {
      labels = {
        env   = local.env
        myapp = "myvalue"
      }
      spec = {
        source = {
          repoURL        = local.workload_repo
        }
        blueprint                = "terraform"
        clusterName              = local.name
        #karpenterInstanceProfile = "${local.name}-${local.node_group_name}" # Activate to enable Karpenter manifests (only when Karpenter add-on will be enabled in the Karpenter module)
        env                      = local.env
      }
    }    
  }

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/terraform-aws-eks-blueprints"
  }
}
~~~~




- Editado

~~~~h
locals {
  name            = basename(path.cwd)
  region          = data.aws_region.current.name
  cluster_version = "1.23"

  vpc_cidr      = "10.0.0.0/16"
  azs           = slice(data.aws_availability_zones.available.names, 0, 3)

  node_group_name = "managed-ondemand"
  env = "dev"

  #---------------------------------------------------------------
  # ARGOCD ADD-ON APPLICATION
  #---------------------------------------------------------------

  addon_application = {
    path               = "chart"
    repo_url           = "https://github.com/aws-samples/eks-blueprints-add-ons.git"
    add_on_application = true
  }

  #---------------------------------------------------------------
  # ARGOCD WORKLOAD APPLICATION
  #---------------------------------------------------------------
  workload_repo = "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"

  workload_application = {
    path               = "envs/dev"
    repo_url           = local.workload_repo
    add_on_application = false
    values = {
      labels = {
        env   = local.env
        myapp = "myvalue"
      }
      spec = {
        source = {
          repoURL        = local.workload_repo
        }
        blueprint                = "terraform"
        clusterName              = local.name
        #karpenterInstanceProfile = "${local.name}-${local.node_group_name}" # Activate to enable Karpenter manifests (only when Karpenter add-on will be enabled in the Karpenter module)
        env                      = local.env
      }
    }    
  }

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/terraform-aws-eks-blueprints"
  }
}

~~~~


nt
Since we forked the workload repository, be sure to use your forked git url, and change [ YOUR GITHUB USER HERE ] with your github login.








# Add Kubernetes Addons Terraform module to main.tf

Add the kubernetes_addons module at the end of our main.tf. To have ArgoCD manage cluster add-ons, we set the argocd_manage_add_ons property to true. This allows the framework to provision necessary AWS resources such as IAM Roles and Policies, but it will not apply Helm charts directly via the Terraform Helm provider, allowing Argo to handle it instead.

We also specify a custom set to configure Argo to expose ArgoCD UI on an aws load balancer. (ideallly we should do it using an ingress but this will be easier for this lab)

This will configure ArgoCD add-on, and allow it to deploy additional kubernetes add-ons using GitOps.

Copy this at the end of main.tf


~~~~h
module "kubernetes_addons" {
  source = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.21.0/modules/kubernetes-addons"

  eks_cluster_id     = module.eks_blueprints.eks_cluster_id

  #---------------------------------------------------------------
  # ARGO CD ADD-ON
  #---------------------------------------------------------------

  enable_argocd         = true
  argocd_manage_add_ons = true # Indicates that ArgoCD is responsible for managing/deploying Add-ons.

  argocd_applications = {
    addons    = local.addon_application
    #workloads = local.workload_application #We comment it for now
  }

  argocd_helm_config = {
    set = [
      {
        name  = "server.service.type"
        value = "LoadBalancer"
      }
    ]
  }

  #---------------------------------------------------------------
  # ADD-ONS - You can add additional addons here
  # https://aws-ia.github.io/terraform-aws-eks-blueprints/add-ons/
  #---------------------------------------------------------------


  enable_aws_load_balancer_controller  = true
  enable_amazon_eks_aws_ebs_csi_driver = true
  enable_aws_for_fluentbit             = true
  enable_metrics_server                = true

}

~~~~














Now that we’ve added the kubernetes_addons module, and have configured ArgoCD, we will apply our changes.
Important
Don't forget to save the cloud9 file as auto-save is not enabled by default.

1
2
# we added a new module, so we must init
terraform init

1
2
# Always a good practice to use a dry-run command
terraform plan

1
2
# apply changes to provision the Platform Team
terraform apply -auto-approve


terraform apply -auto-approve

# View Terraform Output


```bash
Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:

- create

Terraform will perform the following actions:

# module.kubernetes-addons.module.argocd[0].helm_release.argocd_application["addons"] will be created

- resource "helm_release" "argocd_application" {

  - atomic = false
  - chart = ".terraform/modules/kubernetes-addons/modules/kubernetes-addons/argocd/argocd-application"
  - cleanup_on_fail = false
  - create_namespace = false
  - dependency_update = false
  - disable_crd_hooks = false
  - disable_openapi_validation = false
  - disable_webhooks = false
  - force_update = false
  - id = (known after apply)
  - lint = false
  - manifest = (known after apply)
  - max_history = 0
  - metadata = (known after apply)
  - name = "addons"
  - namespace = "argocd"
  - recreate_pods = false
  - render_subchart_notes = true
  - replace = false
  - reset_values = false
  - reuse_values = false
  - skip_crds = false
  - status = "deployed"
  - timeout = 300
  - verify = false
  - version = "0.1.0"
  - wait = true
  - wait_for_jobs = false

  - set {
    - name = "destination.server"
    - value = "https://kubernetes.default.svc"
      }
  - set {
    - name = "name"
    - value = "addons"
      }
  - set {
    - name = "project"
    - value = "default"
      }
  - set {
    - name = "source.helm.releaseName"
    - value = "addons"
      }
  - set {
    - name = "source.helm.values"
    - value = <<-EOT
      "account": "01234567891"
      "clusterName": "tst-stg-mkt-eks"
      "region": "us-west-1"
      "repo_url": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
      EOT
      }
  - set {
    - name = "source.path"
    - value = "chart"
      }
  - set {
    - name = "source.repoUrl"
    - value = "https://github.com/aws-samples/eks-blueprints-add-ons.git"
      }
  - set { + name = "source.targetRevision" + value = "HEAD"
    }
    }

# module.kubernetes-addons.module.argocd[0].helm_release.argocd_application["workloads"] will be created

- resource "helm_release" "argocd_application" {

  - atomic = false
  - chart = ".terraform/modules/kubernetes-addons/modules/kubernetes-addons/argocd/argocd-application"
  - cleanup_on_fail = false
  - create_namespace = false
  - dependency_update = false
  - disable_crd_hooks = false
  - disable_openapi_validation = false
  - disable_webhooks = false
  - force_update = false
  - id = (known after apply)
  - lint = false
  - manifest = (known after apply)
  - max_history = 0
  - metadata = (known after apply)
  - name = "workloads"
  - namespace = "argocd"
  - recreate_pods = false
  - render_subchart_notes = true
  - replace = false
  - reset_values = false
  - reuse_values = false
  - skip_crds = false
  - status = "deployed"
  - timeout = 300
  - verify = false
  - version = "0.1.0"
  - wait = true
  - wait_for_jobs = false

  - set {
    - name = "destination.server"
    - value = "https://kubernetes.default.svc"
      }
  - set {
    - name = "name"
    - value = "workloads"
      }
  - set {
    - name = "project"
    - value = "default"
      }
  - set {
    - name = "source.helm.releaseName"
    - value = "workloads"
      }
  - set {
    - name = "source.helm.values"
    - value = <<-EOT
      "account": "01234567891"
      "clusterName": "tst-stg-mkt-eks"
      "region": "us-west-1"
      "repo_url": "https://github.com/aws-samples/eks-blueprints-workloads.git"
      EOT
      }
  - set {
    - name = "source.path"
    - value = "envs/dev"
      }
  - set {
    - name = "source.repoUrl"
    - value = "https://github.com/aws-samples/eks-blueprints-workloads.git"
      }
  - set { + name = "source.targetRevision" + value = "HEAD"
    }
    }

# module.kubernetes-addons.module.argocd[0].kubernetes_namespace_v1.this will be created

- resource "kubernetes_namespace_v1" "this" {

  - id = (known after apply)

  - metadata { + generation = (known after apply) + labels = { + "app.kubernetes.io/managed-by" = "terraform-eks-blueprints"
    } + name = "argocd" + resource_version = (known after apply) + uid = (known after apply)
    }
    }

# module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0] will be created

- resource "helm_release" "addon" {

  - atomic = false
  - chart = "argo-cd"
  - cleanup_on_fail = false
  - create_namespace = true
  - dependency_update = false
  - description = "The ArgoCD Helm Chart deployment configuration"
  - disable_crd_hooks = false
  - disable_openapi_validation = false
  - disable_webhooks = false
  - force_update = false
  - id = (known after apply)
  - lint = false
  - manifest = (known after apply)
  - max_history = 0
  - metadata = (known after apply)
  - name = "argo-cd"
  - namespace = "argocd"
  - recreate_pods = false
  - render_subchart_notes = true
  - replace = false
  - repository = "https://argoproj.github.io/argo-helm"
  - reset_values = false
  - reuse_values = false
  - skip_crds = false
  - status = "deployed"
  - timeout = 1200
  - values = [

    - <<-EOT
      redis-ha:
      enabled: true

              controller:
                enableStatefulSet: true

              server:
                autoscaling:
                  enabled: true
                  minReplicas: 2

              repoServer:
                autoscaling:
                  enabled: true
                  minReplicas: 2
          EOT,

      ]

  - verify = false
  - version = "3.33.3"
  - wait = true
  - wait_for_jobs = false

  - postrender {}
    }

Plan: 4 to add, 0 to change, 0 to destroy.
╷
│ Warning: Experimental feature "module_variable_optional_attrs" is active
│
│ on .terraform/modules/eks-blueprints-for-terraform/modules/launch-templates/locals.tf line 4, in terraform:
│ 4: experiments = [module_variable_optional_attrs]
│
│ Experimental features are subject to breaking changes in future minor or patch releases, based on feedback.
│
│ If you have feedback on the design of this feature, please open a GitHub issue to discuss it.
│
│ (and 50 more similar warnings elsewhere)
╵

Do you want to perform these actions?
Terraform will perform the actions described above.
Only 'yes' will be accepted to approve.

Enter a value: yes

module.kubernetes-addons.module.argocd[0].kubernetes_namespace_v1.this: Creating...
module.kubernetes-addons.module.argocd[0].kubernetes_namespace_v1.this: Creation complete after 2s [id=argocd]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Creating...
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [10s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [20s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [30s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [40s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [50s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [1m0s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [1m10s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [1m20s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [1m30s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [1m40s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [1m50s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [2m0s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [2m10s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [2m20s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [2m30s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [2m40s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [2m50s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [3m0s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [3m10s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [3m20s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [3m30s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [3m40s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [3m50s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [4m0s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Still creating... [4m10s elapsed]
module.kubernetes-addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Creation complete after 4m19s [id=argo-cd]
module.kubernetes-addons.module.argocd[0].helm_release.argocd_application["addons"]: Creating...
module.kubernetes-addons.module.argocd[0].helm_release.argocd_application["workloads"]: Creating...
module.kubernetes-addons.module.argocd[0].helm_release.argocd_application["addons"]: Creation complete after 2s [id=addons]
module.kubernetes-addons.module.argocd[0].helm_release.argocd_application["workloads"]: Creation complete after 2s [id=workloads]

Apply complete! Resources: 4 added, 0 changed, 0 destroyed.

Outputs:

configure_kubectl = "aws eks --region us-west-2 update-kubeconfig --name eks-blueprint""
private_subnets = [
"subnet-0811ed9f8ccfdb46d",
"subnet-0ef83197e29697391",
]
public_subnets = [
"subnet-0bc9fbb37b55e34e4",
"subnet-0aec53a1833281de4",
]
vpc_id = "vpc-0b7bbf428b0a4dda6"
```



- Efetuando init

~~~~bash
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform init
Initializing modules...
Downloading git::https://github.com/aws-ia/terraform-aws-eks-blueprints.git?ref=v4.21.0 for kubernetes_addons...
- kubernetes_addons in .terraform/modules/kubernetes_addons/modules/kubernetes-addons
- kubernetes_addons.adot_collector_haproxy in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/adot-collector-haproxy
- kubernetes_addons.adot_collector_haproxy.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.adot_collector_haproxy.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.adot_collector_java in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/adot-collector-java
- kubernetes_addons.adot_collector_java.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.adot_collector_java.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.adot_collector_memcached in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/adot-collector-memcached
- kubernetes_addons.adot_collector_memcached.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.adot_collector_memcached.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.adot_collector_nginx in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/adot-collector-nginx
- kubernetes_addons.adot_collector_nginx.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.adot_collector_nginx.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.agones in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/agones
- kubernetes_addons.agones.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.agones.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.airflow in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/airflow
- kubernetes_addons.airflow.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.airflow.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.app_2048 in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/app-2048
- kubernetes_addons.appmesh_controller in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/appmesh-controller
- kubernetes_addons.appmesh_controller.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.appmesh_controller.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.argo_rollouts in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/argo-rollouts
- kubernetes_addons.argo_rollouts.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.argo_rollouts.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.argo_workflows in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/argo-workflows
- kubernetes_addons.argo_workflows.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.argo_workflows.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.argocd in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/argocd
- kubernetes_addons.argocd.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.argocd.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_cloudwatch_metrics in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-cloudwatch-metrics
- kubernetes_addons.aws_cloudwatch_metrics.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_cloudwatch_metrics.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_coredns in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-coredns
- kubernetes_addons.aws_coredns.cluster_proportional_autoscaler in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cluster-proportional-autoscaler
- kubernetes_addons.aws_coredns.cluster_proportional_autoscaler.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_coredns.cluster_proportional_autoscaler.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_coredns.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_coredns.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_ebs_csi_driver in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-ebs-csi-driver
- kubernetes_addons.aws_ebs_csi_driver.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_ebs_csi_driver.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_ebs_csi_driver.irsa_addon in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_efs_csi_driver in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-efs-csi-driver
- kubernetes_addons.aws_efs_csi_driver.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_efs_csi_driver.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_for_fluent_bit in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-for-fluentbit
- kubernetes_addons.aws_for_fluent_bit.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_for_fluent_bit.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_for_fluent_bit.kms in .terraform/modules/kubernetes_addons/modules/aws-kms
- kubernetes_addons.aws_fsx_csi_driver in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-fsx-csi-driver
- kubernetes_addons.aws_fsx_csi_driver.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_fsx_csi_driver.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_kube_proxy in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-kube-proxy
- kubernetes_addons.aws_load_balancer_controller in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-load-balancer-controller
- kubernetes_addons.aws_load_balancer_controller.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_load_balancer_controller.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_node_termination_handler in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-node-termination-handler
- kubernetes_addons.aws_node_termination_handler.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_node_termination_handler.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_privateca_issuer in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-privateca-issuer
- kubernetes_addons.aws_privateca_issuer.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.aws_privateca_issuer.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.aws_vpc_cni in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/aws-vpc-cni
- kubernetes_addons.aws_vpc_cni.irsa_addon in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.calico in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/calico
- kubernetes_addons.calico.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.calico.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.cert_manager in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cert-manager
- kubernetes_addons.cert_manager.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.cert_manager.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.cert_manager_csi_driver in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cert-manager-csi-driver
- kubernetes_addons.cert_manager_csi_driver.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.cert_manager_csi_driver.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.cert_manager_istio_csr in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cert-manager-istio-csr
- kubernetes_addons.cert_manager_istio_csr.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.cert_manager_istio_csr.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.chaos_mesh in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/chaos-mesh
- kubernetes_addons.chaos_mesh.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.chaos_mesh.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.cilium in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cilium
- kubernetes_addons.cilium.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.cilium.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.cluster_autoscaler in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cluster-autoscaler
- kubernetes_addons.cluster_autoscaler.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.cluster_autoscaler.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.consul in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/consul
- kubernetes_addons.consul.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.consul.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.coredns_autoscaler in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cluster-proportional-autoscaler
- kubernetes_addons.coredns_autoscaler.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.coredns_autoscaler.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.crossplane in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/crossplane
- kubernetes_addons.crossplane.aws_provider_irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.crossplane.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.crossplane.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.crossplane.jet_aws_provider_irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.csi_secrets_store_provider_aws in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/csi-secrets-store-provider-aws
- kubernetes_addons.csi_secrets_store_provider_aws.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.csi_secrets_store_provider_aws.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.datadog_operator in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/datadog-operator
- kubernetes_addons.datadog_operator.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.datadog_operator.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.emr_on_eks in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/emr-on-eks
- kubernetes_addons.external_dns in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/external-dns
- kubernetes_addons.external_dns.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.external_dns.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.external_secrets in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/external-secrets
- kubernetes_addons.external_secrets.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.external_secrets.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.fargate_fluentbit in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/fargate-fluentbit
- kubernetes_addons.gatekeeper in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/gatekeeper
- kubernetes_addons.gatekeeper.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.gatekeeper.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.grafana in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/grafana
- kubernetes_addons.grafana.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.grafana.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.ingress_nginx in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/ingress-nginx
- kubernetes_addons.ingress_nginx.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.ingress_nginx.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.karpenter in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/karpenter
- kubernetes_addons.karpenter.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.karpenter.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.keda in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/keda
- kubernetes_addons.keda.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.keda.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.kube_prometheus_stack in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/kube-prometheus-stack
- kubernetes_addons.kube_prometheus_stack.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.kube_prometheus_stack.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.kubecost in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/kubecost
- kubernetes_addons.kubecost.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.kubecost.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.kuberay_operator in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/kuberay-operator
- kubernetes_addons.kuberay_operator.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.kuberay_operator.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.kubernetes_dashboard in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/kubernetes-dashboard
- kubernetes_addons.kubernetes_dashboard.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.kubernetes_dashboard.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.kyverno in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/kyverno
- kubernetes_addons.kyverno.kyverno_helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.kyverno.kyverno_helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.kyverno.kyverno_policies_helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.kyverno.kyverno_policies_helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.kyverno.kyverno_policy_reporter_helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.kyverno.kyverno_policy_reporter_helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.local_volume_provisioner in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/local-volume-provisioner
- kubernetes_addons.local_volume_provisioner.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.local_volume_provisioner.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.metrics_server in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/metrics-server
- kubernetes_addons.metrics_server.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.metrics_server.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.nvidia_device_plugin in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/nvidia-device-plugin
- kubernetes_addons.nvidia_device_plugin.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.nvidia_device_plugin.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
Downloading registry.terraform.io/ondat/ondat-addon/eksblueprints 0.1.2 for kubernetes_addons.ondat...
- kubernetes_addons.ondat in .terraform/modules/kubernetes_addons.ondat
Downloading git::https://github.com/aws-ia/terraform-aws-eks-blueprints.git for kubernetes_addons.ondat.helm_addon...
- kubernetes_addons.ondat.helm_addon in .terraform/modules/kubernetes_addons.ondat.helm_addon/modules/kubernetes-addons/helm-addon
- kubernetes_addons.ondat.helm_addon.irsa in .terraform/modules/kubernetes_addons.ondat.helm_addon/modules/irsa
- kubernetes_addons.opentelemetry_operator in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/opentelemetry-operator
- kubernetes_addons.opentelemetry_operator.cert_manager in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/cert-manager
- kubernetes_addons.opentelemetry_operator.cert_manager.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.opentelemetry_operator.cert_manager.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.opentelemetry_operator.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.opentelemetry_operator.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
Downloading registry.terraform.io/portworx/portworx-addon/eksblueprints 0.0.6 for kubernetes_addons.portworx...
- kubernetes_addons.portworx in .terraform/modules/kubernetes_addons.portworx
Downloading git::https://github.com/aws-ia/terraform-aws-eks-blueprints.git for kubernetes_addons.portworx.helm_addon...
- kubernetes_addons.portworx.helm_addon in .terraform/modules/kubernetes_addons.portworx.helm_addon/modules/kubernetes-addons/helm-addon
- kubernetes_addons.portworx.helm_addon.irsa in .terraform/modules/kubernetes_addons.portworx.helm_addon/modules/irsa
- kubernetes_addons.prometheus in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/prometheus
- kubernetes_addons.prometheus.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.prometheus.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.prometheus.irsa_amp_ingest in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.prometheus.irsa_amp_query in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.promtail in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/promtail
- kubernetes_addons.promtail.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.promtail.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.reloader in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/reloader
- kubernetes_addons.reloader.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.reloader.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.secrets_store_csi_driver in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/secrets-store-csi-driver
- kubernetes_addons.secrets_store_csi_driver.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.secrets_store_csi_driver.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.smb_csi_driver in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/smb-csi-driver
- kubernetes_addons.smb_csi_driver.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.smb_csi_driver.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.spark_history_server in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/spark-history-server
- kubernetes_addons.spark_history_server.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.spark_history_server.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.spark_k8s_operator in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/spark-k8s-operator
- kubernetes_addons.spark_k8s_operator.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.spark_k8s_operator.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.strimzi_kafka_operator in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/strimzi-kafka-operator
- kubernetes_addons.strimzi_kafka_operator.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.strimzi_kafka_operator.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
Downloading registry.terraform.io/sysdiglabs/sysdig-addon/eksblueprints 0.0.3 for kubernetes_addons.sysdig_agent...
- kubernetes_addons.sysdig_agent in .terraform/modules/kubernetes_addons.sysdig_agent
Downloading git::https://github.com/aws-ia/terraform-aws-eks-blueprints.git for kubernetes_addons.sysdig_agent.helm_addon...
- kubernetes_addons.sysdig_agent.helm_addon in .terraform/modules/kubernetes_addons.sysdig_agent.helm_addon/modules/kubernetes-addons/helm-addon
- kubernetes_addons.sysdig_agent.helm_addon.irsa in .terraform/modules/kubernetes_addons.sysdig_agent.helm_addon/modules/irsa
- kubernetes_addons.tetrate_istio in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/tetrate-istio
- kubernetes_addons.tetrate_istio.base in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.tetrate_istio.base.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.tetrate_istio.cni in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.tetrate_istio.cni.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.tetrate_istio.gateway in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.tetrate_istio.gateway.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.tetrate_istio.istiod in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.tetrate_istio.istiod.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.thanos in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/thanos
- kubernetes_addons.thanos.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.thanos.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.traefik in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/traefik
- kubernetes_addons.traefik.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.traefik.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
Downloading registry.terraform.io/hashicorp/hashicorp-vault-eks-addon/aws 1.0.0-rc2 for kubernetes_addons.vault...
- kubernetes_addons.vault in .terraform/modules/kubernetes_addons.vault
- kubernetes_addons.velero in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/velero
- kubernetes_addons.velero.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.velero.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.vpa in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/vpa
- kubernetes_addons.vpa.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.vpa.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa
- kubernetes_addons.yunikorn in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/yunikorn
- kubernetes_addons.yunikorn.helm_addon in .terraform/modules/kubernetes_addons/modules/kubernetes-addons/helm-addon
- kubernetes_addons.yunikorn.helm_addon.irsa in .terraform/modules/kubernetes_addons/modules/irsa

Initializing the backend...

Initializing provider plugins...
- Reusing previous version of gavinbunney/kubectl from the dependency lock file
- Reusing previous version of hashicorp/kubernetes from the dependency lock file
- Reusing previous version of hashicorp/null from the dependency lock file
- Reusing previous version of hashicorp/tls from the dependency lock file
- Reusing previous version of hashicorp/helm from the dependency lock file
- Reusing previous version of hashicorp/aws from the dependency lock file
- Finding hashicorp/time versions matching ">= 0.7.0, >= 0.8.0"...
- Finding latest version of hashicorp/random...
- Reusing previous version of hashicorp/local from the dependency lock file
- Reusing previous version of terraform-aws-modules/http from the dependency lock file
- Reusing previous version of hashicorp/cloudinit from the dependency lock file
- Using previously-installed hashicorp/null v3.2.1
- Using previously-installed hashicorp/tls v4.0.4
- Using previously-installed hashicorp/aws v4.56.0
- Installing hashicorp/time v0.9.1...
- Installed hashicorp/time v0.9.1 (signed by HashiCorp)
- Installing hashicorp/random v3.4.3...
- Installed hashicorp/random v3.4.3 (signed by HashiCorp)
- Using previously-installed gavinbunney/kubectl v1.14.0
- Using previously-installed hashicorp/kubernetes v2.18.1
- Using previously-installed terraform-aws-modules/http v2.4.1
- Using previously-installed hashicorp/cloudinit v2.3.2
- Using previously-installed hashicorp/helm v2.9.0
- Using previously-installed hashicorp/local v2.3.0

Terraform has made some changes to the provider dependency selections recorded
in the .terraform.lock.hcl file. Review those changes and commit them to your
version control system if they represent changes you intended to make.

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
TeamRole:~/environment/eks-blueprint $ 
~~~~




- Plan

~~~~bash
  # module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0] will be created
  + resource "aws_iam_role_policy_attachment" "irsa" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = (known after apply)
    }

  # module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0] will be created
  + resource "kubernetes_service_account_v1" "irsa" {
      + automount_service_account_token = true
      + default_secret_name             = (known after apply)
      + id                              = (known after apply)

      + metadata {
          + annotations      = (known after apply)
          + generation       = (known after apply)
          + name             = "aws-load-balancer-controller-sa"
          + namespace        = "kube-system"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

Plan: 20 to add, 0 to change, 0 to destroy.

─────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't
guarantee to take exactly these actions if you run "terraform apply" now.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
~~~~




- Efetuando apply:

~~~~bash

module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Creation complete after 1s [id=eks-blueprint-aws-for-fluent-bit-sa-irsa-20230302184246496400000004]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role_policy_attachment.irsa[0]: Creation complete after 1s [id=eks-blueprint-ebs-csi-controller-sa-irsa-20230302184246481600000003]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Creation complete after 1s [id=aws-for-fluent-bit/aws-for-fluent-bit-sa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Creation complete after 1s [id=kube-system/aws-load-balancer-controller-sa]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Creation complete after 1s [id=addons]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_key.this: Creation complete after 9s [id=3b6f2a5a-bdd3-4754-adcc-b129c04a00ff]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_alias.this: Creating...
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_cloudwatch_log_group.aws_for_fluent_bit[0]: Creating...
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_alias.this: Creation complete after 0s [id=alias/eks-blueprint-cw-fluent-bit]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_cloudwatch_log_group.aws_for_fluent_bit[0]: Creation complete after 0s [id=/eks-blueprint/worker-fluentbit-logs]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Still creating... [10s elapsed]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Still creating... [20s elapsed]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Still creating... [30s elapsed]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Still creating... [40s elapsed]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Creation complete after 45s [id=eks-blueprint:aws-ebs-csi-driver]

Apply complete! Resources: 20 added, 0 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 
~~~~









# Validate ArgoCD deployment

To validate that ArgoCD is now in our cluster, we can execute the following:

1
kubectl get all -n argocd

Wait about 2 minutes for the LoadBalancer creation, and get it's URL:

1
2
export ARGOCD_SERVER=`kubectl get svc argo-cd-argocd-server -n argocd -o json | jq --raw-output '.status.loadBalancer.ingress[0].hostname'`
echo "https://$ARGOCD_SERVER"

Open a new browser and paste in the url from the previous command. You will now see the ArgoCD UI.
Important
Since ArgoCD UI exposed like this is using self-signed certificate, you'll need to accept the security exception in your browser to access it




TeamRole:~/environment/eks-blueprint $ kubectl get all -n argocd
NAME                                                            READY   STATUS    RESTARTS   AGE
pod/argo-cd-argocd-application-controller-0                     1/1     Running   0          117s
pod/argo-cd-argocd-applicationset-controller-68854c9dd5-6bh8w   1/1     Running   0          117s
pod/argo-cd-argocd-dex-server-786d589d48-cmczg                  1/1     Running   0          117s
pod/argo-cd-argocd-notifications-controller-5c6dccfbd7-mzw58    1/1     Running   0          117s
pod/argo-cd-argocd-repo-server-7f4699495c-8djtr                 1/1     Running   0          117s
pod/argo-cd-argocd-repo-server-7f4699495c-wj77l                 1/1     Running   0          102s
pod/argo-cd-argocd-server-b77c6f499-888pq                       1/1     Running   0          117s
pod/argo-cd-argocd-server-b77c6f499-qtdw2                       1/1     Running   0          102s
pod/argo-cd-redis-ha-haproxy-6f9889946f-f44bj                   1/1     Running   0          117s
pod/argo-cd-redis-ha-haproxy-6f9889946f-jl8lj                   1/1     Running   0          117s
pod/argo-cd-redis-ha-haproxy-6f9889946f-xvf2d                   1/1     Running   0          117s
pod/argo-cd-redis-ha-server-0                                   4/4     Running   0          117s
pod/argo-cd-redis-ha-server-1                                   2/4     Running   0          40s

NAME                                               TYPE           CLUSTER-IP       EXTERNAL-IP                                                              PORT(S)                       AGE
service/argo-cd-argocd-applicationset-controller   ClusterIP      172.20.38.168    <none>                                                                   7000/TCP                      118s
service/argo-cd-argocd-dex-server                  ClusterIP      172.20.222.105   <none>                                                                   5556/TCP,5557/TCP             118s
service/argo-cd-argocd-repo-server                 ClusterIP      172.20.35.51     <none>                                                                   8081/TCP                      118s
service/argo-cd-argocd-server                      LoadBalancer   172.20.87.33     ad78db2e9ced74a77a523381cdfaaa3f-597880980.us-east-1.elb.amazonaws.com   80:30723/TCP,443:31632/TCP    118s
service/argo-cd-redis-ha                           ClusterIP      None             <none>                                                                   6379/TCP,26379/TCP,9121/TCP   118s
service/argo-cd-redis-ha-announce-0                ClusterIP      172.20.146.24    <none>                                                                   6379/TCP,26379/TCP,9121/TCP   118s
service/argo-cd-redis-ha-announce-1                ClusterIP      172.20.35.75     <none>                                                                   6379/TCP,26379/TCP,9121/TCP   118s
service/argo-cd-redis-ha-announce-2                ClusterIP      172.20.90.223    <none>                                                                   6379/TCP,26379/TCP,9121/TCP   118s
service/argo-cd-redis-ha-haproxy                   ClusterIP      172.20.198.30    <none>                                                                   6379/TCP,9101/TCP             118s

NAME                                                       READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/argo-cd-argocd-applicationset-controller   1/1     1            1           118s
deployment.apps/argo-cd-argocd-dex-server                  1/1     1            1           118s
deployment.apps/argo-cd-argocd-notifications-controller    1/1     1            1           118s
deployment.apps/argo-cd-argocd-repo-server                 2/2     2            2           118s
deployment.apps/argo-cd-argocd-server                      2/2     2            2           118s
deployment.apps/argo-cd-redis-ha-haproxy                   3/3     3            3           118s

NAME                                                                  DESIRED   CURRENT   READY   AGE
replicaset.apps/argo-cd-argocd-applicationset-controller-68854c9dd5   1         1         1       117s
replicaset.apps/argo-cd-argocd-dex-server-786d589d48                  1         1         1       117s
replicaset.apps/argo-cd-argocd-notifications-controller-5c6dccfbd7    1         1         1       117s
replicaset.apps/argo-cd-argocd-repo-server-7f4699495c                 2         2         2       117s
replicaset.apps/argo-cd-argocd-server-b77c6f499                       2         2         2       117s
replicaset.apps/argo-cd-redis-ha-haproxy-6f9889946f                   3         3         3       117s

NAME                                                     READY   AGE
statefulset.apps/argo-cd-argocd-application-controller   1/1     117s
statefulset.apps/argo-cd-redis-ha-server                 1/3     117s

NAME                                                                 REFERENCE                               TARGETS                        MINPODS   MAXPODS   REPLICAS   AGE
horizontalpodautoscaler.autoscaling/argo-cd-argocd-repo-server-hpa   Deployment/argo-cd-argocd-repo-server   <unknown>/50%, <unknown>/50%   2         5         2          117s
horizontalpodautoscaler.autoscaling/argo-cd-argocd-server-hpa        Deployment/argo-cd-argocd-server        <unknown>/50%, <unknown>/50%   2         5         2          117s
TeamRole:~/environment/eks-blueprint $ 







TeamRole:~/environment/eks-blueprint $ export ARGOCD_SERVER=`kubectl get svc argo-cd-argocd-server -n argocd -o json | jq --raw-output '.status.loadBalancer.ingress[0].hostname'`
TeamRole:~/environment/eks-blueprint $ echo "https://$ARGOCD_SERVER"
https://ad78db2e9ced74a77a523381cdfaaa3f-597880980.us-east-1.elb.amazonaws.com
TeamRole:~/environment/eks-blueprint $ 




Query for admin password

Retrieve the generated secret for ArgoCD UI admin password. (Note: we could also instead have created a Secret Manager Password for Argo with terraform, see this example 

)

1
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

Login to the UI:

    The username is admin
    The password is: the result of the Query for admin password command above.

At this step you should be able to see Argo UI



TeamRole:~/environment/eks-blueprint $ kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

MiQXxxfu4lVpSCOE
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 





For any future available add-ons 

    you wish to enable, simply follow the steps above by modifying the kubernetes_addons module within the main.tf file and terraform apply again.

In the ArgoUI, you can see that we have severals Applications deployed:

    addons
        aws-load-balancer-controller
        aws_for_fluentbit
        metrics_server

Important
We declare 4 add-ons but only 3 are listed in ArgoUI ?

The EKS Blueprint can deploy Add-ons through EKS managed add-ons 

when they are available, which is the case for the EBS CSI driver. (enable_amazon_eks_aws_ebs_csi_driver = true) In this case it's not ArgoCD that managed thems.

We will now work as a member of team Riker for next module of the workshop.











- No momento, addons foram carregados na UI do ArgoCD.
- 

TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get all -n argocd
NAME                                                            READY   STATUS    RESTARTS   AGE
pod/argo-cd-argocd-application-controller-0                     1/1     Running   0          12m
pod/argo-cd-argocd-applicationset-controller-68854c9dd5-6bh8w   1/1     Running   0          12m
pod/argo-cd-argocd-dex-server-786d589d48-cmczg                  1/1     Running   0          12m
pod/argo-cd-argocd-notifications-controller-5c6dccfbd7-mzw58    1/1     Running   0          12m
pod/argo-cd-argocd-repo-server-7f4699495c-8djtr                 1/1     Running   0          12m
pod/argo-cd-argocd-repo-server-7f4699495c-wj77l                 1/1     Running   0          11m
pod/argo-cd-argocd-server-b77c6f499-888pq                       1/1     Running   0          12m
pod/argo-cd-argocd-server-b77c6f499-qtdw2                       1/1     Running   0          11m
pod/argo-cd-redis-ha-haproxy-6f9889946f-f44bj                   1/1     Running   0          12m
pod/argo-cd-redis-ha-haproxy-6f9889946f-jl8lj                   1/1     Running   0          12m
pod/argo-cd-redis-ha-haproxy-6f9889946f-xvf2d                   1/1     Running   0          12m
pod/argo-cd-redis-ha-server-0                                   4/4     Running   0          12m
pod/argo-cd-redis-ha-server-1                                   4/4     Running   0          10m
pod/argo-cd-redis-ha-server-2                                   4/4     Running   0          9m42s

NAME                                               TYPE           CLUSTER-IP       EXTERNAL-IP                                                              PORT(S)                       AGE
service/argo-cd-argocd-applicationset-controller   ClusterIP      172.20.38.168    <none>                                                                   7000/TCP                      12m
service/argo-cd-argocd-dex-server                  ClusterIP      172.20.222.105   <none>                                                                   5556/TCP,5557/TCP             12m
service/argo-cd-argocd-repo-server                 ClusterIP      172.20.35.51     <none>                                                                   8081/TCP                      12m
service/argo-cd-argocd-server                      LoadBalancer   172.20.87.33     ad78db2e9ced74a77a523381cdfaaa3f-597880980.us-east-1.elb.amazonaws.com   80:30723/TCP,443:31632/TCP    12m
service/argo-cd-redis-ha                           ClusterIP      None             <none>                                                                   6379/TCP,26379/TCP,9121/TCP   12m
service/argo-cd-redis-ha-announce-0                ClusterIP      172.20.146.24    <none>                                                                   6379/TCP,26379/TCP,9121/TCP   12m
service/argo-cd-redis-ha-announce-1                ClusterIP      172.20.35.75     <none>                                                                   6379/TCP,26379/TCP,9121/TCP   12m
service/argo-cd-redis-ha-announce-2                ClusterIP      172.20.90.223    <none>                                                                   6379/TCP,26379/TCP,9121/TCP   12m
service/argo-cd-redis-ha-haproxy                   ClusterIP      172.20.198.30    <none>                                                                   6379/TCP,9101/TCP             12m

NAME                                                       READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/argo-cd-argocd-applicationset-controller   1/1     1            1           12m
deployment.apps/argo-cd-argocd-dex-server                  1/1     1            1           12m
deployment.apps/argo-cd-argocd-notifications-controller    1/1     1            1           12m
deployment.apps/argo-cd-argocd-repo-server                 2/2     2            2           12m
deployment.apps/argo-cd-argocd-server                      2/2     2            2           12m
deployment.apps/argo-cd-redis-ha-haproxy                   3/3     3            3           12m

NAME                                                                  DESIRED   CURRENT   READY   AGE
replicaset.apps/argo-cd-argocd-applicationset-controller-68854c9dd5   1         1         1       12m
replicaset.apps/argo-cd-argocd-dex-server-786d589d48                  1         1         1       12m
replicaset.apps/argo-cd-argocd-notifications-controller-5c6dccfbd7    1         1         1       12m
replicaset.apps/argo-cd-argocd-repo-server-7f4699495c                 2         2         2       12m
replicaset.apps/argo-cd-argocd-server-b77c6f499                       2         2         2       12m
replicaset.apps/argo-cd-redis-ha-haproxy-6f9889946f                   3         3         3       12m

NAME                                                     READY   AGE
statefulset.apps/argo-cd-argocd-application-controller   1/1     12m
statefulset.apps/argo-cd-redis-ha-server                 3/3     12m

NAME                                                                 REFERENCE                               TARGETS                        MINPODS   MAXPODS   REPLICAS   AGE
horizontalpodautoscaler.autoscaling/argo-cd-argocd-repo-server-hpa   Deployment/argo-cd-argocd-repo-server   <unknown>/50%, <unknown>/50%   2         5         2          12m
horizontalpodautoscaler.autoscaling/argo-cd-argocd-server-hpa        Deployment/argo-cd-argocd-server        <unknown>/50%, <unknown>/50%   2         5         2          12m
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl get all -n argocd | grep fluent
TeamRole:~/environment/eks-blueprint $ date
Thu Mar  2 18:55:35 UTC 2023
TeamRole:~/environment/eks-blueprint $ 





- É possível criar os Addons via Terraform.
- Ou é possível criar os Addons via ArgoCD.
são 2 opções disponíveis


# IMPORTANTE
- Necessário cuidar para que o Terraform não destrua o que for aplicado via ArgoCD.














- Aplicar, antes de seguir:


~~~~bash

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
~~~~





- ERROS

[March 2, 2023, 4:16 PM] ‹Chad L.›: I did seem outputs like: An error occurred (AccessDeniedException) when calling the UpdateEnvironment operation: arn:aws:sts::771203811253:assumed-role/mod-9bdf479182da404f-ExampleC9Role-3EEQC58ITIES/i-0f78e864c43d434bf isn't allowed to manage credentials because they're not the environment owner

Conforme time da AWS, é esperado.



- OUTRO ERRO:
Unable to run AWS Toolkit and Git panel. To use these features, please refresh the IDE.

Basta atualizar a página via F5.

















# Deploy Workload

https://catalog.workshops.aws/eks-blueprints-terraform/en-US/040-dev-team-deploy-workload
<https://catalog.workshops.aws/eks-blueprints-terraform/en-US/040-dev-team-deploy-workload>

Now that the cluster is ready and the Platform Team has onboarded the Application Team Riker, they are ready to deploy their workloads.

In the following exercise, you are going to work from your clone of eks-blueprints-workloads 

repo, as a member of team Riker, and you will deploy your workloads only interacting with the git repo.

We will be deploying the team riker static site using ALB in this exercise.
Team Riker Objectives

The team has a static website that they need to publish. Changes should be tracked by source control using GitOps. This means that if a feature branch is merged into main branch, a “sync” is triggered and the app is updated seamlessly.

All of this work will be done within the Riker Team’s environment in EKS/Kubernetes.

The following is a list of key features of this workload:

    A simple static website featuring great ski photography
    In a real environment, we could add a custom FQDN and associated TLS Certificate, but in this lab we can't have custom domain, so we will stay in http on default domains.

As we mentioned earlier in our workshop, we use Helm to package apps and deploy workloads. The Workloads repository is the one recognized by ArgoCD (already setup by Platform Team).


Add App to Workloads Repo
Meet the ArgoCD Workload Application repository

We have created a workload repository sample 
respecting the ArgoCD App of App pattern 

.

Fork this repository if it's not already done, and check it is correctly updated in the locals.tf file.
The Terraform configuration

In our workload_application configuration in locals.tf we previously add configuration to uses your fork and we configure the path to be env/dev. That means that ArgoCD will synchronize the content of this repo/path into our EKS cluster.

~~~~h
workload_repo = "https://github.com/[ PUT YOUR GITHUB USER HERE ]/eks-blueprints-workloads.git"

  workload_application = {
    path               = "envs/dev"
    repo_url           = local.workload_repo
    add_on_application = false
    values = {
      labels = {
        env   = local.env
        myapp = "myvalue"
      }
      spec = {
        source = {
          repoURL        = local.workload_repo
        }
        blueprint                = "terraform"
        clusterName              = local.name
        #karpenterInstanceProfile = "${local.name}-${local.node_group_name}" # Activate to enable Karpenter manifests (only when Karpenter add-on will be enabled in the Karpenter module)
        env                      = local.env
      }
    }    
  }
~~~~

The envs/dev repository

This is how looks like the target for our configuration.

envs/dev/
├── Chart.yaml
├── templates
│   ├── team-burnham.yaml
│   ├── team-carmen.yaml
│   ├── team-geordi.yaml
│   └── team-riker.yaml
└── values.yaml




You can see that this structure is for a Helm Chart 

in which we defined several teams workloads. So if you are familiar with Helm charts, kudos!

The directory as a default env/dev/values.yaml 

which is configured with default values..

1
2
3
4
5
6
spec:
  destination:
    server: https://kubernetes.default.svc
  source:
    repoURL: https://github.com/aws-samples/eks-blueprints-workloads # This will be surcharged by our Terraform workload_application.values.spec.source.repoURL variable.
    targetRevision: main

..but we are relying on our Terraform local workloads_application.values to surcharge thoses parameters (at least we changed the source.repoURL to point to your fork through Terraform).

In the templates 

directory, we can see files representing ArgoCD of Kubernetes's kind Application.
Important
In the Blueprint we only configured the Team Riker as for now. If we deploy as is, all thoses 4 teams will be created, but we only focus on the team-riker in this workshop... So either we can delete the other's team-xxx.yaml files to focus on riker, or you can let Argo deploy thoses additionals workloads but that can be confusing for you.












# The Team Riker Application

Now, let's have a look at the team-riker.yaml 
helm template file. It's an ArgoCD Application 
https://github.com/aws-samples/eks-blueprints-workloads/blob/main/envs/dev/templates/team-riker.yaml#L18
https://github.com/fernandomullerjr/eks-blueprints-workloads/blob/main/envs/dev/templates/team-riker.yaml

defining the team-riker application with code source from the same GitHub repository under path teams/team-riker/dev.

So now, let's look under the teams/team-riker/dev directory structure.

├── Chart.yaml
├── templates
│   ├── 2048.yaml
│   ├── deployment.yaml
│   ├── ingress.yaml
│   └── service.yaml
└── values.yaml

Again, it uses the Helm chart format.

The files under the templates directory are rendered using helm and deployed into the EKS cluster into the team-riker namespace.








# Activate our workload GitOps withing the Terraform code

Remember, in the main.tf file when we configured Argo we choosed to activate only the addon repository. Go back in the cloud9 to update the main.tf and uncomment the workloads application.

argocd_applications = {
    addons = local.addon_application
    workloads = local.workload_application # <- uncomment this line
  }

And then,

1
2
# Always a good practice to use a dry-run command
terraform plan

1
2
# apply changes to provision the Platform Team
terraform apply -auto-approve


- ANTES:

~~~~h
  argocd_applications = {
    addons    = local.addon_application
    #workloads = local.workload_application #We comment it for now
  }
~~~~



- DEPOIS:

~~~~h
  argocd_applications = {
    addons    = local.addon_application
    workloads = local.workload_application #We comment it for now
  }
~~~~



- Efetuando plan:

~~~~bash
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform plan
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
module.kubernetes_addons.data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_region.current: Read complete after 0s [id=us-east-1]
data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_region.current: Reading...
data.aws_region.current: Reading...
module.kubernetes_addons.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.kubernetes_addons.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
data.aws_availability_zones.available: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.kubernetes_addons.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_availability_zones.available: Read complete after 0s [id=us-east-1]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
data.aws_eks_cluster_auth.this: Reading...
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster.cluster: Reading...
module.kubernetes_addons.time_sleep.dataplane: Refreshing state... [id=2023-03-02T18:42:45Z]
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Read complete after 0s [id=2633998141]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Read complete after 0s [id=3161176853]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Read complete after 0s [id=1888929143]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Reading...
module.kubernetes_addons.module.argocd[0].kubernetes_namespace_v1.this[0]: Refreshing state... [id=argocd]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Refreshing state... [id=team-riker]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-access]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_iam_policy.aws_ebs_csi_driver[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-aws-ebs-csi-driver-irsa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].aws_iam_policy.aws_load_balancer_controller: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-lb-irsa]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Refreshing state... [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Refreshing state... [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_iam_policy.aws_for_fluent_bit: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-fluentbit]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 1s [id=eks-blueprint]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Read complete after 0s [id=1146648495]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_key.this: Refreshing state... [id=3b6f2a5a-bdd3-4754-adcc-b129c04a00ff]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-sa-role]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.kubernetes_addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Refreshing state... [id=argo-cd]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint-cw-fluent-bit]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_cloudwatch_log_group.aws_for_fluent_bit[0]: Refreshing state... [id=/eks-blueprint/worker-fluentbit-logs]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa-20230302184246481600000003]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=kube-system/aws-load-balancer-controller-sa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa-20230302184246481500000002]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Read complete after 1s [id=aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit/aws-for-fluent-bit-sa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa-20230302184246496400000004]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Refreshing state... [id=eks-blueprint:aws-ebs-csi-driver]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Refreshing state... [id=addons]

Note: Objects have changed outside of Terraform

Terraform detected the following changes made outside of Terraform since the last "terraform apply" which may have affected this plan:

  # module.kubernetes_addons.module.argocd[0].module.helm_addon.helm_release.addon[0] has changed
  ~ resource "helm_release" "addon" {
        id                         = "argo-cd"
        name                       = "argo-cd"
        # (29 unchanged attributes hidden)

      ~ postrender {
          + args = []
        }

        # (1 unchanged block hidden)
    }


Unless you have made equivalent changes to your configuration, or ignored the relevant attributes using ignore_changes, the following plan may include actions to undo or respond to these changes.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"] will be created
  + resource "helm_release" "argocd_application" {
      + atomic                     = false
      + chart                      = ".terraform/modules/kubernetes_addons/modules/kubernetes-addons/argocd/argocd-application/helm"
      + cleanup_on_fail            = false
      + create_namespace           = false
      + dependency_update          = false
      + disable_crd_hooks          = false
      + disable_openapi_validation = false
      + disable_webhooks           = false
      + force_update               = false
      + id                         = (known after apply)
      + lint                       = false
      + manifest                   = (known after apply)
      + max_history                = 0
      + metadata                   = (known after apply)
      + name                       = "workloads"
      + namespace                  = "argocd"
      + pass_credentials           = false
      + recreate_pods              = false
      + render_subchart_notes      = true
      + replace                    = false
      + reset_values               = false
      + reuse_values               = false
      + skip_crds                  = false
      + status                     = "deployed"
      + timeout                    = 300
      + values                     = [
          + <<-EOT
                "ignoreDifferences": []
            EOT,
        ]
      + verify                     = false
      + version                    = "0.1.0"
      + wait                       = true
      + wait_for_jobs              = false

      + set {
          + name  = "destination.server"
          + type  = "string"
          + value = "https://kubernetes.default.svc"
        }
      + set {
          + name  = "name"
          + type  = "string"
          + value = "workloads"
        }
      + set {
          + name  = "project"
          + type  = "string"
          + value = "default"
        }
      + set {
          + name  = "source.helm.releaseName"
          + type  = "string"
          + value = "workloads"
        }
      + set {
          + name  = "source.helm.values"
          + type  = "auto"
          + value = <<-EOT
                "account": "537174683150"
                "clusterName": "eks-blueprint"
                "labels":
                  "env": "dev"
                  "myapp": "myvalue"
                "region": "us-east-1"
                "repoUrl": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
                "spec":
                  "blueprint": "terraform"
                  "clusterName": "eks-blueprint"
                  "env": "dev"
                  "source":
                    "repoURL": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
            EOT
        }
      + set {
          + name  = "source.path"
          + type  = "string"
          + value = "envs/dev"
        }
      + set {
          + name  = "source.repoUrl"
          + type  = "string"
          + value = "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
        }
      + set {
          + name  = "source.targetRevision"
          + type  = "string"
          + value = "HEAD"
        }
    }

Plan: 1 to add, 0 to change, 0 to destroy.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't guarantee to take exactly these actions if you run "terraform apply" now.
TeamRole:~/environment/eks-blueprint $ 
~~~~




- Efetuando apply:
terraform apply -auto-approve


TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform apply -auto-approve
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
data.aws_caller_identity.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_region.current: Reading...
data.aws_availability_zones.available: Reading...
module.eks_blueprints.data.aws_region.current: Reading...
data.aws_region.current: Reading...
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.kubernetes_addons.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
module.kubernetes_addons.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_availability_zones.available: Read complete after 0s [id=us-east-1]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster_auth.this: Reading...
module.kubernetes_addons.time_sleep.dataplane: Refreshing state... [id=2023-03-02T18:42:45Z]
data.aws_eks_cluster.cluster: Reading...
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Reading...
module.kubernetes_addons.module.argocd[0].kubernetes_namespace_v1.this[0]: Refreshing state... [id=argocd]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Refreshing state... [id=team-riker]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-access]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Refreshing state... [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Refreshing state... [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Reading...
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Read complete after 0s [id=3161176853]
module.kubernetes_addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Refreshing state... [id=argo-cd]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-sa-role]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_iam_policy.aws_for_fluent_bit: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-fluentbit]
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Read complete after 0s [id=2633998141]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Read complete after 0s [id=1888929143]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Read complete after 0s [id=1146648495]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.kubernetes_addons.module.aws_load_balancer_controller[0].aws_iam_policy.aws_load_balancer_controller: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-lb-irsa]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_iam_policy.aws_ebs_csi_driver[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-aws-ebs-csi-driver-irsa]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_key.this: Refreshing state... [id=3b6f2a5a-bdd3-4754-adcc-b129c04a00ff]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint-cw-fluent-bit]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_cloudwatch_log_group.aws_for_fluent_bit[0]: Refreshing state... [id=/eks-blueprint/worker-fluentbit-logs]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit/aws-for-fluent-bit-sa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa-20230302184246496400000004]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=kube-system/aws-load-balancer-controller-sa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa-20230302184246481500000002]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa-20230302184246481600000003]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Read complete after 1s [id=aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Refreshing state... [id=eks-blueprint:aws-ebs-csi-driver]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Refreshing state... [id=addons]

Note: Objects have changed outside of Terraform

Terraform detected the following changes made outside of Terraform since the last "terraform apply" which may have affected this plan:

  # module.kubernetes_addons.module.argocd[0].module.helm_addon.helm_release.addon[0] has changed
  ~ resource "helm_release" "addon" {
        id                         = "argo-cd"
        name                       = "argo-cd"
        # (29 unchanged attributes hidden)

      ~ postrender {
          + args = []
        }

        # (1 unchanged block hidden)
    }


Unless you have made equivalent changes to your configuration, or ignored the relevant attributes using ignore_changes, the following plan may include actions to undo or respond to these changes.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"] will be created
  + resource "helm_release" "argocd_application" {
      + atomic                     = false
      + chart                      = ".terraform/modules/kubernetes_addons/modules/kubernetes-addons/argocd/argocd-application/helm"
      + cleanup_on_fail            = false
      + create_namespace           = false
      + dependency_update          = false
      + disable_crd_hooks          = false
      + disable_openapi_validation = false
      + disable_webhooks           = false
      + force_update               = false
      + id                         = (known after apply)
      + lint                       = false
      + manifest                   = (known after apply)
      + max_history                = 0
      + metadata                   = (known after apply)
      + name                       = "workloads"
      + namespace                  = "argocd"
      + pass_credentials           = false
      + recreate_pods              = false
      + render_subchart_notes      = true
      + replace                    = false
      + reset_values               = false
      + reuse_values               = false
      + skip_crds                  = false
      + status                     = "deployed"
      + timeout                    = 300
      + values                     = [
          + <<-EOT
                "ignoreDifferences": []
            EOT,
        ]
      + verify                     = false
      + version                    = "0.1.0"
      + wait                       = true
      + wait_for_jobs              = false

      + set {
          + name  = "destination.server"
          + type  = "string"
          + value = "https://kubernetes.default.svc"
        }
      + set {
          + name  = "name"
          + type  = "string"
          + value = "workloads"
        }
      + set {
          + name  = "project"
          + type  = "string"
          + value = "default"
        }
      + set {
          + name  = "source.helm.releaseName"
          + type  = "string"
          + value = "workloads"
        }
      + set {
          + name  = "source.helm.values"
          + type  = "auto"
          + value = <<-EOT
                "account": "537174683150"
                "clusterName": "eks-blueprint"
                "labels":
                  "env": "dev"
                  "myapp": "myvalue"
                "region": "us-east-1"
                "repoUrl": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
                "spec":
                  "blueprint": "terraform"
                  "clusterName": "eks-blueprint"
                  "env": "dev"
                  "source":
                    "repoURL": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
            EOT
        }
      + set {
          + name  = "source.path"
          + type  = "string"
          + value = "envs/dev"
        }
      + set {
          + name  = "source.repoUrl"
          + type  = "string"
          + value = "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
        }
      + set {
          + name  = "source.targetRevision"
          + type  = "string"
          + value = "HEAD"
        }
    }

Plan: 1 to add, 0 to change, 0 to destroy.
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Creating...
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Creation complete after 1s [id=workloads]

Apply complete! Resources: 1 added, 0 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 




Since our changes are pushed to the main branch of our workload git repository, ArgoCD is now aware of them and will automatically sync the main branch with our EKS cluster. Your ArgoCD dashboard should look like the following.

If changes are not appearing, you may need to resync the workloads Application in ArgoCD UI: Click on workloads and click on the sync button.



You can Click in the ArgoUI on the team-riker box.

Then you will see all the kubernetes objects that are deployed in the team-riker namespace













# Add our website manifest for the new SkiApp

We were asked as member of Team Riker, to deploy a new website in our Kubernetes namespace, the SkiApp application. For that, we will need to add some kubernetes manifests to the teams/team-riker/dev/templates directory. There are several ways to do it, you can either clone your repo, edit the files with your favorite IDE, and pushed them back to github, or you can uses GitHub Codespace to have a remote VsCode and make change there, or you can uses the GitHub interface to push your changes.

Open your clone of the Workloads Repository 
in your IDE (or GitHub Codespace 

)
Create a GitHub CodeSpace from your Fork (better with chrome of Firefox)

We are going to create a new directory and files Under teams/team-riker/dev/templates, which represent the website manifests we want to deploy. From the root directory of the git repository run the following command:

1
2
3
4
5
mkdir -p teams/team-riker/dev/templates/alb-skiapp

curl https://static.us-east-1.prod.workshops.aws/public/02e0eb5d-ad0c-4108-a3f6-459f42bf46e4/assets/alb-skiapp/deployment.yaml --output teams/team-riker/dev/templates/alb-skiapp/deployment.yaml
curl https://static.us-east-1.prod.workshops.aws/public/02e0eb5d-ad0c-4108-a3f6-459f42bf46e4/assets/alb-skiapp/ingress.yaml --output teams/team-riker/dev/templates/alb-skiapp/ingress.yaml
curl https://static.us-east-1.prod.workshops.aws/public/02e0eb5d-ad0c-4108-a3f6-459f42bf46e4/assets/alb-skiapp/service.yaml --output teams/team-riker/dev/templates/alb-skiapp/service.yaml

.. or do it with the GitHub interface:

Now the repository should be like

$ tree teams/team-riker/dev/templates/alb-skiapp

teams/team-riker/dev/templates/alb-skiapp
├── deployment.yaml
├── ingress.yaml
└── service.yaml






fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ mkdir -p teams/team-riker/dev/templates/alb-skiapp
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ curl https://static.us-east-1.prod.workshops.aws/public/02e0eb5d-ad0c-4108-a3f6-459f42bf46e4/assets/alb-skiapp/deployment.yaml --output teams/team-riker/dev/templates/alb-skiapp/deployment.yaml
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   543  100   543    0     0    748      0 --:--:-- --:--:-- --:--:--   748
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ curl https://static.us-east-1.prod.workshops.aws/public/02e0eb5d-ad0c-4108-a3f6-459f42bf46e4/assets/alb-skiapp/ingress.yaml --output teams/team-riker/dev/templates/alb-skiapp/ingress.yaml
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   926  100   926    0     0   1326      0 --:--:-- --:--:-- --:--:--  1324
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ curl https://static.us-east-1.prod.workshops.aws/public/02e0eb5d-ad0c-4108-a3f6-459f42bf46e4/assets/alb-skiapp/service.yaml --output teams/team-riker/dev/templates/alb-skiapp/service.yaml
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100   204  100   204    0     0    264      0 --:--:-- --:--:-- --:--:--   264
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ ls -lhasp teams/team-riker/dev/templates/alb-skiapp
total 20K
4.0K drwxr-xr-x 2 fernando fernando 4.0K Mar  2 16:29 ./
4.0K drwxr-xr-x 3 fernando fernando 4.0K Mar  2 16:29 ../
4.0K -rw-r--r-- 1 fernando fernando  543 Mar  2 16:29 deployment.yaml
4.0K -rw-r--r-- 1 fernando fernando  926 Mar  2 16:29 ingress.yaml
4.0K -rw-r--r-- 1 fernando fernando  204 Mar  2 16:29 service.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ date
Thu 02 Mar 2023 04:29:39 PM -03
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git status
On branch main
Your branch is up to date with 'origin/main'.

Untracked files:
  (use "git add <file>..." to include in what will be committed)

        teams/team-riker/dev/templates/alb-skiapp/

nothing added to commit but untracked files present (use "git add" to track)
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$




2
3
git add .
git commit -m "feature: adding skiapp which uses alb"
git push









# See it went live in ArgoCD

Go back to the ArgoCD UI and click on the Sync button in the team-riker application. You should see your last commit on the top of the screen, and the new application appearing.

To access our Ski App application, you now can click on the skiapp-ingress as shown in red in the previous picture.
Important
It can takes few minutes for the load balancer to create and the Domain name to be propagated.


- No Menu do ArgoCD, nas aplicações
clicar no " team-riker"
https://ad78db2e9ced74a77a523381cdfaaa3f-597880980.us-east-1.elb.amazonaws.com/applications/argocd/team-riker?view=tree&resource=
em " team-riker"
tem um ingress sendo deployado que é do "SkiApp"
Nele tem um botão que direciona para a URL dele e abre o app:
http://k8s-teamrike-rikering-535ca2cd9a-1266283885.us-east-1.elb.amazonaws.com/
http://k8s-riker-c64bab81ac-419166569.us-east-1.elb.amazonaws.com/


Important
For a production application, we would have configure our ingress to use a custom domain name, and uses the external-dns add-on to dynamically configure our route53 hosted zone from the ingress configuration. You can find a more complete example in this example 
of the eks blueprints.

So our Riker Application Team as successfully published their website to the EKS cluster provided by the Platform Team. This pattern can be reused with your actual applications, If you want to see more EKS blueprints teams and ArgoCD integration, you can go to next module.
























# Blue/Green Deployments with Argo Rollouts

In this module, we use Argo Rollouts to implement an advanced deployment strategy called blue-green. There are many benefits in using this strategy including zero downtime deployments.

The Kubernetes Deployment already uses rolling updates but does not give you enough control. Here is a comparison.
Features	Kubernetes Deployment	Argo Rollouts
Blue/Green	No	Yes
Control over Rollout Speed	No	Yes
Easy traffic Management	No	Yes
Verify using External Metrics	No	Yes
Automate Rollout/rollback based on analysis	No	Yes
		
Important
This workshop is focused on how to enable and try Argo Rollouts in the context of using EKS Blueprints for Terraform We do not provide a deep-dive into Argo Rollouts. To learn more about Argo Rollouts view the docs 
How Argo Rollouts Blue/Green Deployments Work

The Rollout will configure the preview service (Green) to send traffic to the new version while the active service (Blue) continues to receive production traffic. Once we are satisfied, we promote the preview service to be the new active service.

Argo Rollouts Architecture

FIGURE 1 - Argo Rollouts Blue/Green Deployment Strategy

    source: Argo Rollouts Docs 

Scenario

Marketing would like to run functional testing on a new version of the Skiapp before it starts to serve production traffic.

The current version we are using is sharepointoscar/skiapp:v1 which is pulled from Docker Hub. The new and improved version is appropriately tagged sharepointoscar/skiapp:v2 and includes less global navigation items.

Marketing decided there were too many global navigation items.


## Step 1: Enable Argo Rollouts Add-on

Earlier in the Bootstrap ArgoCD section, we added the kubernetes_addons module. We enabled several add-ons using the EKS Blueprints for Terraform IaC. Argo Rollouts comes out of the box as an add-on, so all we need to do is enable it.

Go to the main.tf file and under the kubernetes_addons module. Add the enable_argo_rollouts = true, to enable the add-on as shown below.

~~~~H
module "kubernetes_addons" {
source = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.21.0/modules/kubernetes-addons"
... ommitted content for brevity ...

  enable_aws_load_balancer_controller  = true
  enable_amazon_eks_aws_ebs_csi_driver = true
  enable_aws_for_fluentbit             = true
  enable_metrics_server                = true
  enable_argo_rollouts                 = true # <-- Add this line
}
~~~~

Next apply our changes via Terraform.

1
terraform apply -auto-approve



- Adicionando no main.tf:
enable_argo_rollouts                 = true


- Aplicando:
terraform apply -auto-approve




TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform apply -auto-approve
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
data.aws_availability_zones.available: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
data.aws_region.current: Reading...
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_region.current: Reading...
module.kubernetes_addons.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.kubernetes_addons.data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
module.kubernetes_addons.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.kubernetes_addons.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_availability_zones.available: Read complete after 0s [id=us-east-1]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.kubernetes_addons.time_sleep.dataplane: Refreshing state... [id=2023-03-02T18:42:45Z]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster.cluster: Reading...
data.aws_eks_cluster_auth.this: Reading...
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 1s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 1s [id=eks-blueprint]
data.aws_eks_cluster.cluster: Read complete after 1s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-access]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Refreshing state... [id=team-riker]
module.kubernetes_addons.module.argocd[0].kubernetes_namespace_v1.this[0]: Refreshing state... [id=argocd]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role-binding]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Refreshing state... [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Refreshing state... [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-sa-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Read complete after 0s [id=3161176853]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_iam_policy.aws_for_fluent_bit: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-fluentbit]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Read complete after 0s [id=1146648495]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Read complete after 0s [id=1888929143]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.kubernetes_addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Refreshing state... [id=argo-cd]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_key.this: Refreshing state... [id=3b6f2a5a-bdd3-4754-adcc-b129c04a00ff]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_iam_policy.aws_ebs_csi_driver[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-aws-ebs-csi-driver-irsa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Read complete after 1s [id=2633998141]
module.kubernetes_addons.module.aws_load_balancer_controller[0].aws_iam_policy.aws_load_balancer_controller: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-lb-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_cloudwatch_log_group.aws_for_fluent_bit[0]: Refreshing state... [id=/eks-blueprint/worker-fluentbit-logs]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint-cw-fluent-bit]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit/aws-for-fluent-bit-sa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa-20230302184246496400000004]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa-20230302184246481600000003]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Read complete after 1s [id=aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Refreshing state... [id=eks-blueprint:aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=kube-system/aws-load-balancer-controller-sa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa-20230302184246481500000002]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Refreshing state... [id=addons]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Refreshing state... [id=workloads]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
  ~ update in-place

Terraform will perform the following actions:

  # module.kubernetes_addons.module.argo_rollouts[0].kubernetes_namespace_v1.this[0] will be created
  + resource "kubernetes_namespace_v1" "this" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "argo-rollouts"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"] will be updated in-place
  ~ resource "helm_release" "argocd_application" {
        id                         = "addons"
        name                       = "addons"
        # (27 unchanged attributes hidden)

      + set {
          + name  = "source.helm.values"
          + type  = "auto"
          + value = <<-EOT
                "account": "537174683150"
                "argoRollouts":
                  "enable": "true"
                "awsForFluentBit":
                  "enable": "true"
                  "logGroupName": "/eks-blueprint/worker-fluentbit-logs"
                  "serviceAccountName": "aws-for-fluent-bit-sa"
                "awsLoadBalancerController":
                  "enable": "true"
                  "serviceAccountName": "aws-load-balancer-controller-sa"
                "clusterName": "eks-blueprint"
                "metricsServer":
                  "enable": "true"
                "region": "us-east-1"
                "repoUrl": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
            EOT
        }
      - set {
          - name  = "source.helm.values" -> null
          - type  = "auto" -> null
          - value = <<-EOT
                "account": "537174683150"
                "awsForFluentBit":
                  "enable": "true"
                  "logGroupName": "/eks-blueprint/worker-fluentbit-logs"
                  "serviceAccountName": "aws-for-fluent-bit-sa"
                "awsLoadBalancerController":
                  "enable": "true"
                  "serviceAccountName": "aws-load-balancer-controller-sa"
                "clusterName": "eks-blueprint"
                "metricsServer":
                  "enable": "true"
                "region": "us-east-1"
                "repoUrl": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
            EOT -> null
        }

        # (7 unchanged blocks hidden)
    }

Plan: 1 to add, 1 to change, 0 to destroy.
module.kubernetes_addons.module.argo_rollouts[0].kubernetes_namespace_v1.this[0]: Creating...
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifying... [id=addons]
module.kubernetes_addons.module.argo_rollouts[0].kubernetes_namespace_v1.this[0]: Creation complete after 0s [id=argo-rollouts]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifications complete after 1s [id=addons]

Apply complete! Resources: 1 added, 1 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 






















# Validate Argo Rollouts Installation

One of the first things to check is the new namespace argo-rollouts

1
kubectl get all -n argo-rollouts

NAME                                 READY   STATUS    RESTARTS   AGE
pod/argo-rollouts-5656b86459-j9bjg   1/1     Running   0          3h38m
pod/argo-rollouts-5656b86459-rhthq   1/1     Running   0          3h38m

NAME                            READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/argo-rollouts   2/2     2            2           3h38m

NAME                                       DESIRED   CURRENT   READY   AGE
replicaset.apps/argo-rollouts-5656b86459   2         2         2       3h38m

The ArgoCD dashboard should also show you the installation is green and all items are healthy.
Accessing ArgoCD UI
For instructions on how to access the ArgoCD UI, take a look at our previous steps. Bootstrap ArgoCD



- No meu ambiente:

~~~~bash
TeamRole:~/environment/eks-blueprint $ kubectl get all -n argo-rollouts

NAME                                 READY   STATUS    RESTARTS   AGE
pod/argo-rollouts-555667ffc9-968sz   1/1     Running   0          96s
pod/argo-rollouts-555667ffc9-zrdgk   1/1     Running   0          96s

NAME                            READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/argo-rollouts   2/2     2            2           98s

NAME                                       DESIRED   CURRENT   READY   AGE
replicaset.apps/argo-rollouts-555667ffc9   2         2         2       97s
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
~~~~









# Step 2: Deploy App Using Blue/Green Strategy

Now that we have Argo Rollouts fully configured, it is time to take it for a spin.

Using the skiapp we previously used, we are going to deploy using the blue-green deployment strategy.

Let's define the Rollout!
Add rollout.yaml to alb-skiapp folder

In our previous module Add App to Workloads Repo , we created the alb-skiapp folder and added the ingress.yaml, deployment.yaml and service.yaml files.

We now need to add an additional file called rollout.yaml that will replace the deployment.yaml to that folder and we will end up with the following structure.

├── Chart.yaml
├── templates
│   ├── alb-skiapp
│   │   ├── deployment.yaml
│   │   ├── ingress.yaml
│   │   ├── rollout.yaml
│   │   └── service.yaml
│   ├── deployment.yaml
│   ├── ingress.yaml
│   └── service.yaml
└── values.yaml

Once you've located the workloads repository and alb-skiapp folder, let's add additional file to define the Rollout.



- Estrutura atual do meu repo do Workload:

~~~~bash

fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ ls -lhasp teams/team-riker/dev/templates/alb-skiapp
total 20K
4.0K drwxr-xr-x 2 fernando fernando 4.0K Mar  2 16:29 ./
4.0K drwxr-xr-x 3 fernando fernando 4.0K Mar  2 16:29 ../
4.0K -rw-r--r-- 1 fernando fernando  543 Mar  2 16:29 deployment.yaml
4.0K -rw-r--r-- 1 fernando fernando  926 Mar  2 16:29 ingress.yaml
4.0K -rw-r--r-- 1 fernando fernando  204 Mar  2 16:29 service.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ ls -lhasp teams/team-riker/dev/templates/
total 28K
4.0K drwxr-xr-x 3 fernando fernando 4.0K Mar  2 16:29 ./
4.0K drwxr-xr-x 3 fernando fernando 4.0K Mar  2 16:19 ../
4.0K -rw-r--r-- 1 fernando fernando 3.3K Mar  2 16:19 2048.yaml
4.0K drwxr-xr-x 2 fernando fernando 4.0K Mar  2 16:29 alb-skiapp/
4.0K -rw-r--r-- 1 fernando fernando  819 Mar  2 16:19 deployment.yaml
4.0K -rw-r--r-- 1 fernando fernando 1.6K Mar  2 16:19 ingress.yaml
4.0K -rw-r--r-- 1 fernando fernando  218 Mar  2 16:19 service.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$

~~~~


# Add Rollout YAML definition

Inside the alb-skiapp folder, add the following definition in a new file named rollout.yaml. We are adding 3 different resources, which include a Rollout, a Service to use for the Preview of our app, and lastly we create an Ingress to use with our Preview Service.

Paste this command in your codespace or copy rollout.yaml 

file, and copy it in the correct directory.

cat << EOF > teams/team-riker/dev/templates/alb-skiapp/rollout.yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: skiapp-rollout
  namespace: team-riker
  labels:
    app: skiapp
spec:
  replicas: 3
  revisionHistoryLimit: 1
  selector:
    matchLabels:
      app: skiapp
  template:
    metadata:
      labels:
        app: skiapp
    spec:
      containers:
      - name: skiapp
        image: sharepointoscar/skiapp:v1
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        resources:
            requests:
                memory: "64Mi"
                cpu: "250m"
            limits:
                memory: "128Mi"
                cpu: "500m"
      {{ if .Values.spec.karpenterInstanceProfile }}
      nodeSelector: # <- add nodeselector, toleration and spread constraitns
        team: default
        type: karpenter
      tolerations:
        - key: 'karpenter'
          operator: 'Exists'
          effect: 'NoSchedule'
      {{ end }}
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: skiapp          
      tolerations:
        - key: 'karpenter'
          operator: 'Exists'
          effect: 'NoSchedule'                
  strategy:
    blueGreen:
      autoPromotionEnabled: false
      activeService: skiapp-service
      previewService: skiapp-service-preview
---
apiVersion: v1
kind: Service
metadata:
  name: skiapp-service-preview
  namespace: team-riker
spec:
  ports:
    - port: 80
      targetPort: 8080
      protocol: TCP
  type: NodePort
  selector:
    app: skiapp
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: skiapp-ingress-preview
  namespace: team-riker
  annotations:
    alb.ingress.kubernetes.io/group.name: riker-preview
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}]'
    alb.ingress.kubernetes.io/tags: 'Environment=dev,Team=Riker'
spec:
  ingressClassName: alb
  rules:
  - host: 
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: skiapp-service-preview
            port:
              number: 80
EOF

This Creates A Rollout to managed our application with

    nodeSelector to select Karpenter nodes (only if we provide the Karpenter Profile in values)
    toleration to allow scheduling on Karpenter taints (only if we provide the Karpenter Profile in values)
    topologySpreadConstraints to spread our workloads on each AZ
    a Service for the preview version
    An ingress to expose the preview Service

Save the file in your source code. We can also delete the old deployment.yaml file as now we uses the Rollout to create our pods.

1
2
3
git add .
git commit -m "feature: adding rollout resource"
git push





- Criado o rollout.yaml:

~~~~bash
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ ls -lhasp teams/team-riker/dev/templates/alb-skiapp
total 24K
4.0K drwxr-xr-x 2 fernando fernando 4.0K Mar  2 17:09 ./
4.0K drwxr-xr-x 3 fernando fernando 4.0K Mar  2 16:29 ../
4.0K -rw-r--r-- 1 fernando fernando  543 Mar  2 16:29 deployment.yaml
4.0K -rw-r--r-- 1 fernando fernando  926 Mar  2 16:29 ingress.yaml
4.0K -rw-r--r-- 1 fernando fernando 2.3K Mar  2 17:09 rollout.yaml
4.0K -rw-r--r-- 1 fernando fernando  204 Mar  2 16:29 service.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ date
Thu 02 Mar 2023 05:09:43 PM -03
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$

~~~~



- Subindo ele:
git add .
git commit -m "feature: adding rollout resource"
git push


~~~~bash

fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git add .
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git commit -m "feature: adding rollout resource"
[main e0b5d98] feature: adding rollout resource
 1 file changed, 97 insertions(+)
 create mode 100644 teams/team-riker/dev/templates/alb-skiapp/rollout.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git push
Enumerating objects: 14, done.
Counting objects: 100% (14/14), done.
Delta compression using up to 8 threads
Compressing objects: 100% (8/8), done.
Writing objects: 100% (8/8), 1.58 KiB | 1.58 MiB/s, done.
Total 8 (delta 3), reused 0 (delta 0)
remote: Resolving deltas: 100% (3/3), completed with 3 local objects.
To github.com:fernandomullerjr/eks-blueprints-workloads.git
   63c45e3..e0b5d98  main -> main
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$


~~~~




















# Go to the Argo Dashboard and see the Rollout deploy. If it is not deployed yet, you can click on the Sync button to force it.

We already have installed Argo Rollouts Kubectl plugin 

as part of our bootstrap script eksinit.sh.

Check the status of the Rollout with the following command:

1
kubectl argo rollouts list rollouts -n team-riker

1
2
NAME            STRATEGY   STATUS        STEP  SET-WEIGHT  READY  DESIRED  UP-TO-DATE  AVAILABLE
skiapp-rollout  BlueGreen  Healthy       -     -           3/3    3        3           3

We can also Watch the status of the Rollout. Open this command in a new terminal:

1
kubectl argo rollouts get rollout skiapp-rollout -n team-riker -w

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
Name:            skiapp-rollout
Namespace:       team-riker
Status:          ✔ Healthy
Strategy:        BlueGreen
Images:          sharepointoscar/skiapp:v2 (stable, active)
Replicas:
  Desired:       3
  Current:       3
  Updated:       3
  Ready:         3
  Available:     3

NAME                                        KIND        STATUS     AGE    INFO
⟳ skiapp-rollout                            Rollout     ✔ Healthy  5m43s  
└──# revision:1                                                           
   └──⧉ skiapp-rollout-7594c7c67f           ReplicaSet  ✔ Healthy  5m42s  stable,active
      ├──□ skiapp-rollout-7594c7c67f-494bk  Pod         ✔ Running  5m42s  ready:1/1
      ├──□ skiapp-rollout-7594c7c67f-l4vcx  Pod         ✔ Running  5m42s  ready:1/1
      └──□ skiapp-rollout-7594c7c67f-khkxh  Pod         ✔ Running  4m48s  ready:1/1















- Não aparecia o rollout no Namespace:

TeamRole:~/environment/eks-blueprint $ kubectl argo rollouts list rollouts -n team-riker
No resources found.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl argo rollouts list rollouts -n team-riker
No resources found.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 




- Foi necessário forçar um SYNC no app "team-riker":

APP HEALTH
 Healthy
CURRENT SYNC STATUS
Synced
To main (e0b5d98)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
feature: adding skiapp which uses alb
LAST SYNC RESULT
Sync OK
To e0b5d98
Succeeded 5 minutes ago (Thu Mar 02 2023 17:16:32 GMT-0300)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
feature: adding rollout resource



- Agora trouxe o rollout:

TeamRole:~/environment/eks-blueprint $ kubectl argo rollouts list rollouts -n team-riker
NAME            STRATEGY   STATUS        STEP  SET-WEIGHT  READY  DESIRED  UP-TO-DATE  AVAILABLE
skiapp-rollout  BlueGreen  Healthy       -     -           3/3    3        3           3        
TeamRole:~/environment/eks-blueprint $ 




kubectl argo rollouts get rollout skiapp-rollout -n team-riker -w

TeamRole:~/environment/eks-blueprint $ 
Name:            skiapp-rollout
Namespace:       team-riker
Status:          ✔ Healthy
Strategy:        BlueGreen
Images:          sharepointoscar/skiapp:v1 (stable, active)
Replicas:
  Desired:       3
  Current:       3
  Updated:       3
  Ready:         3
  Available:     3

NAME                                        KIND        STATUS     AGE  INFO
⟳ skiapp-rollout                            Rollout     ✔ Healthy  88s  
└──# revision:1                                                         
   └──⧉ skiapp-rollout-7cddc49665           ReplicaSet  ✔ Healthy  88s  stable,active
      ├──□ skiapp-rollout-7cddc49665-95lcc  Pod         ✔ Running  88s  ready:1/1
      ├──□ skiapp-rollout-7cddc49665-mp6v4  Pod         ✔ Running  88s  ready:1/1
      └──□ skiapp-rollout-7cddc49665-qr972  Pod         ✔ Running  88s  ready:1/1
^CTeamRole:~/environment/eks-blueprint $ 



















# How is exposed the Rollout ?

Remember, we started to create a deployment.yaml, and a service.yaml exposed with it's ingress.yaml that has created our Load Balancer.

Look at the live service.yaml yaml content, you should see an evolution in it's Pod Selectors.

1
kubectl get svc skiapp-service -o json | jq ".spec.selector"

1
2
3
4
{
  "app": "skiapp",
  "rollouts-pod-template-hash": "7594c7c67f"
}

The rollouts-pod-template-hash has been added by the Argo Rollout controller so that our service only target pods that are created by the Rollout skiapp-rollout Kubernetes object.

This means that our pods from the deployment.yaml file are no more exposed through the service. We can remove the deploymen.yaml file from our Workload Reposiroty:

    Delete the deployment.yaml file and commit the change
    Once ArgoCD has delete the deployment, check you still have access to the skiapp application.





TeamRole:~/environment/eks-blueprint $ kubectl get svc skiapp-service -o json | jq ".spec.selector"
Error from server (NotFound): services "skiapp-service" not found
TeamRole:~/environment/eks-blueprint $ 


kubectl get svc skiapp-service -o json -n team-riker | jq ".spec.selector"


TeamRole:~/environment/eks-blueprint $ kubectl get svc skiapp-service -o json -n team-riker | jq ".spec.selector"
{
  "app": "skiapp",
  "rollouts-pod-template-hash": "7cddc49665"
}
TeamRole:~/environment/eks-blueprint $ 




TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ history | tail
   95  ls
   96  terraform plan
   97  terraform apply -auto-approve
   98  kubectl get all -n argo-rollouts
   99  kubectl argo rollouts list rollouts -n team-riker
  100  kubectl argo rollouts get rollout skiapp-rollout -n team-riker -w
  101  kubectl get svc skiapp-service -o json | jq ".spec.selector"
  102  kubectl get svc -A
  103  kubectl get svc skiapp-service -o json -n team-riker | jq ".spec.selector"
  104  history | tail
TeamRole:~/environment/eks-blueprint $ 



- No argo

APP HEALTH
 Healthy
CURRENT SYNC STATUS
Synced
To main (7733f76)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
feature: adding skiapp which uses alb
LAST SYNC RESULT
Sync OK
To 7733f76
Succeeded 5 minutes ago (Thu Mar 02 2023 17:21:37 GMT-0300)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
removendo o deployment.yaml da pasta do app skiapp.














# Step 3: Deploy a Green Version of Skiapp

Now that we have our Blue version running of the skiapp, we want to deploy a Green version which visually has the top navigation changed, we've removed several items from the navigation menu.
Update Rollout in Source Control and delete deployment.yaml

Since our Rollout definition within our Workloads repo, let's change the image used, and set it to V2 (Green).

In the rollout.yaml, change the image to sharepointoscar/skiapp:v2 as shown below.

1
2
3
4
5
6
7
8
apiVersion: argoproj.io/v1alpha1
kind: Rollout
...
    spec:
      containers:
        - name: skiapp
          image: sharepointoscar/skiapp:v2
...

Once you've checked in the file in source control and merged with the main branch, ArgoCD will pick up the change and sync and update the Rollout so that the Preview Service shows the (Green) v2 version of our app.

You should see with the kubectl argo rollouts list rollouts -n team-riker -w you run previously, that we have 2 revisions in our rollout:

    revision:1 is stable and active
    revision:2 is in preview

View it on Argo Rollout Dashboard

To be able to open the Argo Rollout Dashboard inside Cloud9, we need to forward port 8080 to 3100

1
2
3
sudo iptables -t nat -I OUTPUT -o lo -p tcp --dport 8080 -j REDIRECT --to-port 3100
sudo iptables -I INPUT -p tcp --dport 3100
sudo iptables -I INPUT -p tcp --dport 8080





kubectl argo rollouts get rollout skiapp-rollout -n team-riker -w






- No argo

APP HEALTH
 Suspended
CURRENT SYNC STATUS
Synced
To main (7f10445)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
feature: adding skiapp which uses alb
LAST SYNC RESULT
Sync OK
To 7f10445
Succeeded 5 minutes ago (Thu Mar 02 2023 17:25:37 GMT-0300)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
ajustando version para v2 no rollout.yaml





TeamRole:~/environment/eks-blueprint $ 
Name:            skiapp-rollout
Namespace:       team-riker
Status:          ॥ Paused
Message:         BlueGreenPause
Strategy:        BlueGreen
Images:          sharepointoscar/skiapp:v1 (stable, active)
                 sharepointoscar/skiapp:v2 (preview)
Replicas:
  Desired:       3
  Current:       6
  Updated:       3
  Ready:         3
  Available:     3

NAME                                        KIND        STATUS     AGE    INFO
⟳ skiapp-rollout                            Rollout     ॥ Paused   9m39s  
├──# revision:2                                                           
│  └──⧉ skiapp-rollout-6c6d4bf568           ReplicaSet  ✔ Healthy  35s    preview
│     ├──□ skiapp-rollout-6c6d4bf568-k4xl2  Pod         ✔ Running  34s    ready:1/1
│     ├──□ skiapp-rollout-6c6d4bf568-tdw5s  Pod         ✔ Running  34s    ready:1/1
│     └──□ skiapp-rollout-6c6d4bf568-x7m9c  Pod         ✔ Running  34s    ready:1/1
└──# revision:1                                                           
   └──⧉ skiapp-rollout-7cddc49665           ReplicaSet  ✔ Healthy  9m39s  stable,active
      ├──□ skiapp-rollout-7cddc49665-95lcc  Pod         ✔ Running  9m39s  ready:1/1
      ├──□ skiapp-rollout-7cddc49665-mp6v4  Pod         ✔ Running  9m39s  ready:1/1
      └──□ skiapp-rollout-7cddc49665-qr972  Pod         ✔ Running  9m39s  ready:1/1









# Create the Argo Rollouts Dashboard using the following command.

1
kubectl argo rollouts dashboard

Open the Browser Preview by using the menu option Tools > Preview > Preview Running Application.



# PENDENTE
- Argo Rollout Dashboard


























-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
# Autoscaling with Karpenter

In this module, you will learn how to maintain your Kubernetes clusters at any scale using Karpenter 

.

Karpenter is an open-source autoscaling project built for Kubernetes. Karpenter is designed to provide the right compute resources to match your application’s needs in seconds, instead of minutes by observing the aggregate resource requests of unschedulable pods and makes decisions to launch and terminate nodes to minimize scheduling latencies.

GitHub Create File

Karpenter is a node lifecycle management solution used to scale your Kubernetes Cluster. It observes incoming pods and launches the right instances for the situation. Instance selection decisions are intent based and driven by the specification of incoming pods, including resource requests and scheduling constraints.

For now, our EKS blueprint cluster is configured to run with an EKS Managed Node Group 

, which has deployed a minimum set of On-Demand instances that we will use to deploy Kubernetes controllers on it.
Important
we could also have choosen to deploy Karpenter on Fargate 
instead like in this example 
After that we will use Karpenter to deploy a mix of On-Demand and Spot instances to showcase a few of the benefits of running a group-less auto scaler. EC2 Spot 

Instances allow you to architect for optimizations on cost and scale.
Step 0: Create the EC2 Spot Linked Role

We continue as Platform Team member and create the EC2 Spot Linked role 

, which is necessary to exist in your account in order to let you launch Spot instances.
Important
This step is only necessary if this is the first time you’re using EC2 Spot in this account. If the role has already been successfully created, you will see: An error occurred (InvalidInput) when calling the CreateServiceLinkedRole operation: Service role name AWSServiceRoleForEC2Spot has been taken in this account, please try a different suffix. Just ignore the error and proceed with the rest of the workshop.

1
aws iam create-service-linked-role --aws-service-name spot.amazonaws.com


- Criando a role:


TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ aws iam create-service-linked-role --aws-service-name spot.amazonaws.com

{
    "Role": {
        "Path": "/aws-service-role/spot.amazonaws.com/",
        "RoleName": "AWSServiceRoleForEC2Spot",
        "RoleId": "AROAX2EQ3FYHBWBU4M2FW",
        "Arn": "arn:aws:iam::537174683150:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot",
        "CreateDate": "2023-03-02T20:39:57+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "sts:AssumeRole"
                    ],
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "spot.amazonaws.com"
                        ]
                    }
                }
            ]
        }
    }
}
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 









# Step 1: Configure Karpenter Add-On

    In our Terraform code in main.tf in kubernetes_addons changed the enable_karpenter to true, and add the following lines.

1
2
3
4
5
6
7
8
  enable_karpenter                     = true
  karpenter_helm_config = {
    awsInterruptionQueueName = data.aws_arn.queue.resource
    awsDefaultInstanceProfile = "${local.name}-${local.node_group_name}"
  }
  karpenter_node_iam_instance_profile        = module.karpenter.instance_profile_name
  karpenter_enable_spot_termination_handling = true
  karpenter_sqs_queue_arn                    = module.karpenter.queue_arn  







Still in main.tf, add this nes karpenter module, that will create an SQS queue and Eventbridge event rule for Karpenter to utilize for spot termination handling, capacity rebalancing.

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
################################################################################
# Karpenter
################################################################################

data "aws_arn" "queue" {
  arn = module.karpenter.queue_arn
}

# Creates Karpenter native node termination handler resources and IAM instance profile
module "karpenter" {
  source  = "terraform-aws-modules/eks/aws//modules/karpenter"
  version = "~> 19.5"

  cluster_name           = local.name
  create_irsa            = false # IRSA will be created by the kubernetes-addons module

  tags = local.tags
}












# Deploy Karpenter Add-On

Now run Terraform plan to see our modifications.

1
terraform init

Now run Terraform plan to see our modifications.

1
terraform plan

Now run Terraform apply to deploy our modifications.

1
terraform apply --auto-approve

Once the deployment is done you should see Karpenter appears in the cluster:

1
kubectl get pods -n karpenter

NAME                         READY   STATUS    RESTARTS   AGE
karpenter-776657675b-d8sgt   2/2     Running   0          88s
karpenter-776657675b-gj8h4   2/2     Running   0          88s

Congrats, You successfully Installed Karpenter in your EKS cluster.




- Fazendo init:


TeamRole:~/environment/eks-blueprint $ terraform init
Initializing modules...
Downloading registry.terraform.io/terraform-aws-modules/eks/aws 19.10.0 for karpenter...
- karpenter in .terraform/modules/karpenter/modules/karpenter

Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/null from the dependency lock file
- Reusing previous version of hashicorp/cloudinit from the dependency lock file
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/helm from the dependency lock file
- Reusing previous version of gavinbunney/kubectl from the dependency lock file
- Reusing previous version of hashicorp/local from the dependency lock file
- Reusing previous version of hashicorp/random from the dependency lock file
- Reusing previous version of hashicorp/tls from the dependency lock file
- Reusing previous version of hashicorp/kubernetes from the dependency lock file
- Reusing previous version of terraform-aws-modules/http from the dependency lock file
- Reusing previous version of hashicorp/time from the dependency lock file
- Using previously-installed hashicorp/local v2.3.0
- Using previously-installed hashicorp/random v3.4.3
- Using previously-installed hashicorp/kubernetes v2.18.1
- Using previously-installed hashicorp/time v0.9.1
- Using previously-installed hashicorp/null v3.2.1
- Using previously-installed hashicorp/aws v4.56.0
- Using previously-installed gavinbunney/kubectl v1.14.0
- Using previously-installed terraform-aws-modules/http v2.4.1
- Using previously-installed hashicorp/cloudinit v2.3.2
- Using previously-installed hashicorp/helm v2.9.0
- Using previously-installed hashicorp/tls v4.0.4

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 






- Efetuando plan:



TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform plan
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_partition.current: Reading...
module.kubernetes_addons.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_caller_identity.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.karpenter.data.aws_partition.current: Reading...
module.kubernetes_addons.data.aws_region.current: Reading...
module.eks_blueprints.data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.karpenter.data.aws_caller_identity.current: Reading...
data.aws_caller_identity.current: Reading...
module.karpenter.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_availability_zones.available: Reading...
data.aws_region.current: Read complete after 0s [id=us-east-1]
module.karpenter.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.karpenter.data.aws_iam_policy_document.assume_role[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.karpenter.data.aws_iam_policy_document.assume_role[0]: Read complete after 0s [id=2560088296]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
data.aws_availability_zones.available: Read complete after 1s [id=us-east-1]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 1s [id=1163348263]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
data.aws_eks_cluster.cluster: Reading...
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster_auth.this: Reading...
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.kubernetes_addons.time_sleep.dataplane: Refreshing state... [id=2023-03-02T18:42:45Z]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
module.kubernetes_addons.module.argocd[0].kubernetes_namespace_v1.this[0]: Refreshing state... [id=argocd]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.kubernetes_addons.module.argo_rollouts[0].kubernetes_namespace_v1.this[0]: Refreshing state... [id=argo-rollouts]
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role-binding]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Refreshing state... [id=team-riker]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-access]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 1s [id=537174683150]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Refreshing state... [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Read complete after 1s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Refreshing state... [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Read complete after 0s [id=3161176853]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 1s [id=eks-blueprint]
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_iam_policy.aws_for_fluent_bit: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-fluentbit]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Read complete after 0s [id=1888929143]
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Read complete after 0s [id=2633998141]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Reading...
module.kubernetes_addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Refreshing state... [id=argo-cd]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_iam_policy.aws_ebs_csi_driver[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-aws-ebs-csi-driver-irsa]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.kubernetes_addons.module.aws_load_balancer_controller[0].aws_iam_policy.aws_load_balancer_controller: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-lb-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-sa-role]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Read complete after 0s [id=1146648495]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_key.this: Refreshing state... [id=3b6f2a5a-bdd3-4754-adcc-b129c04a00ff]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint-cw-fluent-bit]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_cloudwatch_log_group.aws_for_fluent_bit[0]: Refreshing state... [id=/eks-blueprint/worker-fluentbit-logs]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa-20230302184246481600000003]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Read complete after 0s [id=aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Refreshing state... [id=eks-blueprint:aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit/aws-for-fluent-bit-sa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa-20230302184246496400000004]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=kube-system/aws-load-balancer-controller-sa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa-20230302184246481500000002]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Refreshing state... [id=workloads]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Refreshing state... [id=addons]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
  ~ update in-place
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_arn.queue will be read during apply
  # (config refers to values not yet known)
 <= data "aws_arn" "queue" {
      + account   = (known after apply)
      + arn       = (known after apply)
      + id        = (known after apply)
      + partition = (known after apply)
      + region    = (known after apply)
      + resource  = (known after apply)
      + service   = (known after apply)
    }

  # module.karpenter.data.aws_iam_policy_document.queue[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "queue" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "sqs:SendMessage",
            ]
          + resources = [
              + (known after apply),
            ]
          + sid       = "SqsWrite"

          + principals {
              + identifiers = [
                  + "events.amazonaws.com",
                  + "sqs.amazonaws.com",
                ]
              + type        = "Service"
            }
        }
    }

  # module.karpenter.aws_cloudwatch_event_rule.this["health_event"] will be created
  + resource "aws_cloudwatch_event_rule" "this" {
      + arn            = (known after apply)
      + description    = "Karpenter interrupt - AWS health event"
      + event_bus_name = "default"
      + event_pattern  = jsonencode(
            {
              + detail-type = [
                  + "AWS Health Event",
                ]
              + source      = [
                  + "aws.health",
                ]
            }
        )
      + id             = (known after apply)
      + is_enabled     = true
      + name           = (known after apply)
      + name_prefix    = "KarpenterHealthEvent-"
      + tags           = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all       = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
    }

  # module.karpenter.aws_cloudwatch_event_rule.this["instance_rebalance"] will be created
  + resource "aws_cloudwatch_event_rule" "this" {
      + arn            = (known after apply)
      + description    = "Karpenter interrupt - EC2 instance rebalance recommendation"
      + event_bus_name = "default"
      + event_pattern  = jsonencode(
            {
              + detail-type = [
                  + "EC2 Instance Rebalance Recommendation",
                ]
              + source      = [
                  + "aws.ec2",
                ]
            }
        )
      + id             = (known after apply)
      + is_enabled     = true
      + name           = (known after apply)
      + name_prefix    = "KarpenterInstanceRebalance-"
      + tags           = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all       = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
    }

  # module.karpenter.aws_cloudwatch_event_rule.this["instance_state_change"] will be created
  + resource "aws_cloudwatch_event_rule" "this" {
      + arn            = (known after apply)
      + description    = "Karpenter interrupt - EC2 instance state-change notification"
      + event_bus_name = "default"
      + event_pattern  = jsonencode(
            {
              + detail-type = [
                  + "EC2 Instance State-change Notification",
                ]
              + source      = [
                  + "aws.ec2",
                ]
            }
        )
      + id             = (known after apply)
      + is_enabled     = true
      + name           = (known after apply)
      + name_prefix    = "KarpenterInstanceStateChange-"
      + tags           = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all       = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
    }

  # module.karpenter.aws_cloudwatch_event_rule.this["spot_interupt"] will be created
  + resource "aws_cloudwatch_event_rule" "this" {
      + arn            = (known after apply)
      + description    = "Karpenter interrupt - EC2 spot instance interruption warning"
      + event_bus_name = "default"
      + event_pattern  = jsonencode(
            {
              + detail-type = [
                  + "EC2 Spot Instance Interruption Warning",
                ]
              + source      = [
                  + "aws.ec2",
                ]
            }
        )
      + id             = (known after apply)
      + is_enabled     = true
      + name           = (known after apply)
      + name_prefix    = "KarpenterSpotInterrupt-"
      + tags           = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all       = {
          + "Blueprint"   = "eks-blueprint"
          + "ClusterName" = "eks-blueprint"
          + "GithubRepo"  = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
    }

  # module.karpenter.aws_cloudwatch_event_target.this["health_event"] will be created
  + resource "aws_cloudwatch_event_target" "this" {
      + arn            = (known after apply)
      + event_bus_name = "default"
      + id             = (known after apply)
      + rule           = (known after apply)
      + target_id      = "KarpenterInterruptionQueueTarget"
    }

  # module.karpenter.aws_cloudwatch_event_target.this["instance_rebalance"] will be created
  + resource "aws_cloudwatch_event_target" "this" {
      + arn            = (known after apply)
      + event_bus_name = "default"
      + id             = (known after apply)
      + rule           = (known after apply)
      + target_id      = "KarpenterInterruptionQueueTarget"
    }

  # module.karpenter.aws_cloudwatch_event_target.this["instance_state_change"] will be created
  + resource "aws_cloudwatch_event_target" "this" {
      + arn            = (known after apply)
      + event_bus_name = "default"
      + id             = (known after apply)
      + rule           = (known after apply)
      + target_id      = "KarpenterInterruptionQueueTarget"
    }

  # module.karpenter.aws_cloudwatch_event_target.this["spot_interupt"] will be created
  + resource "aws_cloudwatch_event_target" "this" {
      + arn            = (known after apply)
      + event_bus_name = "default"
      + id             = (known after apply)
      + rule           = (known after apply)
      + target_id      = "KarpenterInterruptionQueueTarget"
    }

  # module.karpenter.aws_iam_instance_profile.this[0] will be created
  + resource "aws_iam_instance_profile" "this" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "Karpenter-eks-blueprint-"
      + path        = "/"
      + role        = (known after apply)
      + tags        = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all    = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id   = (known after apply)
    }

  # module.karpenter.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = "EKSNodeAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "Karpenter-eks-blueprint-"
      + path                  = "/"
      + tags                  = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.karpenter.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = (known after apply)
    }

  # module.karpenter.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
      + role       = (known after apply)
    }

  # module.karpenter.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
      + role       = (known after apply)
    }

  # module.karpenter.aws_sqs_queue.this[0] will be created
  + resource "aws_sqs_queue" "this" {
      + arn                               = (known after apply)
      + content_based_deduplication       = false
      + deduplication_scope               = (known after apply)
      + delay_seconds                     = 0
      + fifo_queue                        = false
      + fifo_throughput_limit             = (known after apply)
      + id                                = (known after apply)
      + kms_data_key_reuse_period_seconds = (known after apply)
      + max_message_size                  = 262144
      + message_retention_seconds         = 300
      + name                              = "Karpenter-eks-blueprint"
      + name_prefix                       = (known after apply)
      + policy                            = (known after apply)
      + receive_wait_time_seconds         = 0
      + redrive_allow_policy              = (known after apply)
      + redrive_policy                    = (known after apply)
      + sqs_managed_sse_enabled           = true
      + tags                              = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + tags_all                          = {
          + "Blueprint"  = "eks-blueprint"
          + "GithubRepo" = "github.com/aws-ia/terraform-aws-eks-blueprints"
        }
      + url                               = (known after apply)
      + visibility_timeout_seconds        = 30
    }

  # module.karpenter.aws_sqs_queue_policy.this[0] will be created
  + resource "aws_sqs_queue_policy" "this" {
      + id        = (known after apply)
      + policy    = (known after apply)
      + queue_url = (known after apply)
    }

  # module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"] will be updated in-place
  ~ resource "helm_release" "argocd_application" {
        id                         = "addons"
        name                       = "addons"
        # (27 unchanged attributes hidden)

      - set {
          - name  = "source.helm.values" -> null
          - type  = "auto" -> null
          - value = <<-EOT
                "account": "537174683150"
                "argoRollouts":
                  "enable": "true"
                "awsForFluentBit":
                  "enable": "true"
                  "logGroupName": "/eks-blueprint/worker-fluentbit-logs"
                  "serviceAccountName": "aws-for-fluent-bit-sa"
                "awsLoadBalancerController":
                  "enable": "true"
                  "serviceAccountName": "aws-load-balancer-controller-sa"
                "clusterName": "eks-blueprint"
                "metricsServer":
                  "enable": "true"
                "region": "us-east-1"
                "repoUrl": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
            EOT -> null
        }
      + set {
          + name  = "source.helm.values"
          + type  = "auto"
          + value = (known after apply)
        }

        # (7 unchanged blocks hidden)
    }

  # module.kubernetes_addons.module.karpenter[0].data.aws_arn.queue[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_arn" "queue" {
      + account   = (known after apply)
      + arn       = (known after apply)
      + id        = (known after apply)
      + partition = (known after apply)
      + region    = (known after apply)
      + resource  = (known after apply)
      + service   = (known after apply)
    }

  # module.kubernetes_addons.module.karpenter[0].data.aws_iam_policy_document.karpenter will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "karpenter" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "ec2:CreateFleet",
              + "ec2:CreateLaunchTemplate",
              + "ec2:CreateTags",
              + "ec2:DeleteLaunchTemplate",
              + "ec2:DescribeAvailabilityZones",
              + "ec2:DescribeImages",
              + "ec2:DescribeInstanceTypeOfferings",
              + "ec2:DescribeInstanceTypes",
              + "ec2:DescribeInstances",
              + "ec2:DescribeLaunchTemplates",
              + "ec2:DescribeSecurityGroups",
              + "ec2:DescribeSpotPriceHistory",
              + "ec2:DescribeSubnets",
              + "ec2:RunInstances",
              + "iam:PassRole",
              + "pricing:GetProducts",
              + "ssm:GetParameter",
            ]
          + effect    = "Allow"
          + resources = [
              + "*",
            ]
          + sid       = "Karpenter"
        }
      + statement {
          + actions   = [
              + "ec2:TerminateInstances",
            ]
          + effect    = "Allow"
          + resources = [
              + "*",
            ]
          + sid       = "ConditionalEC2Termination"

          + condition {
              + test     = "StringLike"
              + values   = [
                  + "*karpenter*",
                ]
              + variable = "ec2:ResourceTag/Name"
            }
        }
      + statement {
          + actions   = [
              + "sqs:DeleteMessage",
              + "sqs:GetQueueAttributes",
              + "sqs:GetQueueUrl",
              + "sqs:ReceiveMessage",
            ]
          + resources = [
              + (known after apply),
            ]
        }
    }

  # module.kubernetes_addons.module.karpenter[0].aws_iam_policy.karpenter will be created
  + resource "aws_iam_policy" "karpenter" {
      + arn         = (known after apply)
      + description = "IAM Policy for Karpenter"
      + id          = (known after apply)
      + name        = "eks-blueprint-karpenter"
      + path        = "/"
      + policy      = (known after apply)
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0] will be created
  + resource "aws_iam_role" "irsa" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRoleWithWebIdentity"
                      + Condition = {
                          + StringLike = {
                              + "oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672:aud" = "sts.amazonaws.com"
                              + "oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672:sub" = "system:serviceaccount:karpenter:karpenter"
                            }
                        }
                      + Effect    = "Allow"
                      + Principal = {
                          + Federated = "arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + description           = "AWS IAM Role for the Kubernetes service account karpenter."
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "eks-blueprint-karpenter-irsa"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0] will be created
  + resource "aws_iam_role_policy_attachment" "irsa" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "eks-blueprint-karpenter-irsa"
    }

  # module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0] will be created
  + resource "kubernetes_namespace_v1" "irsa" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "karpenter"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + timeouts {
          + delete = "15m"
        }
    }

  # module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0] will be created
  + resource "kubernetes_service_account_v1" "irsa" {
      + automount_service_account_token = true
      + default_secret_name             = (known after apply)
      + id                              = (known after apply)

      + metadata {
          + annotations      = (known after apply)
          + generation       = (known after apply)
          + name             = "karpenter"
          + namespace        = "karpenter"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

Plan: 20 to add, 1 to change, 0 to destroy.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't guarantee to take exactly these actions if you run "terraform apply" now.
TeamRole:~/environment/eks-blueprint $ 












module.karpenter.aws_sqs_queue_policy.this[0]: Creating...
module.karpenter.aws_cloudwatch_event_target.this["instance_state_change"]: Creation complete after 0s [id=KarpenterInstanceStateChange-20230302204541345000000001-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["health_event"]: Creation complete after 0s [id=KarpenterHealthEvent-20230302204541353400000003-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["spot_interupt"]: Creation complete after 0s [id=KarpenterSpotInterrupt-20230302204541345100000002-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["instance_rebalance"]: Creation complete after 0s [id=KarpenterInstanceRebalance-20230302204541354200000004-KarpenterInterruptionQueueTarget]
module.kubernetes_addons.module.karpenter[0].aws_iam_policy.karpenter: Creation complete after 0s [id=arn:aws:iam::537174683150:policy/eks-blueprint-karpenter]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifying... [id=addons]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Creation complete after 0s [id=karpenter]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Creation complete after 0s [id=eks-blueprint-karpenter-irsa]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Creation complete after 0s [id=eks-blueprint-karpenter-irsa-2023030220460746410000000a]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifications complete after 1s [id=addons]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Creation complete after 1s [id=karpenter/karpenter]
module.karpenter.aws_sqs_queue_policy.this[0]: Still creating... [10s elapsed]




module.karpenter.aws_cloudwatch_event_target.this["instance_state_change"]: Creation complete after 0s [id=KarpenterInstanceStateChange-20230302204541345000000001-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["health_event"]: Creation complete after 0s [id=KarpenterHealthEvent-20230302204541353400000003-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["spot_interupt"]: Creation complete after 0s [id=KarpenterSpotInterrupt-20230302204541345100000002-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["instance_rebalance"]: Creation complete after 0s [id=KarpenterInstanceRebalance-20230302204541354200000004-KarpenterInterruptionQueueTarget]
module.kubernetes_addons.module.karpenter[0].aws_iam_policy.karpenter: Creation complete after 0s [id=arn:aws:iam::537174683150:policy/eks-blueprint-karpenter]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifying... [id=addons]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Creation complete after 0s [id=karpenter]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Creation complete after 0s [id=eks-blueprint-karpenter-irsa]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Creating...
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Creation complete after 0s [id=eks-blueprint-karpenter-irsa-2023030220460746410000000a]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifications complete after 1s [id=addons]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Creation complete after 1s [id=karpenter/karpenter]
module.karpenter.aws_sqs_queue_policy.this[0]: Still creating... [10s elapsed]
module.karpenter.aws_sqs_queue_policy.this[0]: Still creating... [20s elapsed]
module.karpenter.aws_sqs_queue_policy.this[0]: Creation complete after 25s [id=https://sqs.us-east-1.amazonaws.com/537174683150/Karpenter-eks-blueprint]

Apply complete! Resources: 20 added, 1 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 







TeamRole:~/environment/eks-blueprint $ kubectl get pods -n karpenter

NAME                      READY   STATUS    RESTARTS      AGE
karpenter-f6fd9b7-5xxvt   1/1     Running   1 (43s ago)   48s
karpenter-f6fd9b7-gfkt7   1/1     Running   1 (44s ago)   48s
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
















# Step 2: Create a Karpenter Provisioner within our ArgoCD workload repository
in the workload repository

In order for our cluster to take advantage of Karpenter, we need to configure a provisioner 

Go back to your ArgoCD workload repository fork in codespace and create a new file karpenter.yaml inside the teams/team-riker/dev/templates. Copy/Paste the following command in your codespace shell to create the file.
Important
This provisioner may also be enabled centrally by the platform team, I used this way in the workshop for ease.

Add the karpenter.yaml file by copying the new command in your codespace or by Downloading the file : karpenter.yaml 

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
cat << EOF > teams/team-riker/dev/templates/karpenter.yaml 
{{ if .Values.spec.karpenterInstanceProfile }}
apiVersion: karpenter.k8s.aws/v1alpha1
kind: AWSNodeTemplate
metadata:
  name: karpenter-default
  labels:
    {{- toYaml .Values.labels | nindent 4 }}  
spec:
  instanceProfile: {{ .Values.spec.clusterName }}-managed-ondemand
  subnetSelector:
    kubernetes.io/cluster/{{ .Values.spec.clusterName }}: '*'
    kubernetes.io/role/internal-elb: '1' # to select only private subnets
  securityGroupSelector:
    aws:eks:cluster-name: '{{ .Values.spec.clusterName }}' # Choose only security groups of nodes
  tags:
    karpenter.sh/cluster_name: {{.Values.spec.clusterName}}
    karpenter.sh/provisioner: default
  metadataOptions:
    httpEndpoint: enabled
    httpProtocolIPv6: disabled
    httpPutResponseHopLimit: 2
    httpTokens: required
---
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: default
  labels:
    {{- toYaml .Values.labels | nindent 4 }}
spec:
  consolidation:
    enabled: true
  #ttlSecondsAfterEmpty: 60 # mutual exclusive with consolitation
  requirements:
    - key: "karpenter.k8s.aws/instance-category"
      operator: In
      values: ["c", "m"]
    - key: karpenter.k8s.aws/instance-cpu
      operator: Lt
      values:
        - '33'    
    - key: 'kubernetes.io/arch'
      operator: In
      values: ['amd64']
    - key: karpenter.sh/capacity-type
      operator: In
      values: ['on-demand']
    - key: kubernetes.io/os
      operator: In
      values:
        - linux
  consolidation:
    enabled: true
  providerRef:
    name: karpenter-default

  ttlSecondsUntilExpired: 2592000 # 30 Days = 60 * 60 * 24 * 30 Seconds;
  
  # Priority given to the provisioner when the scheduler considers which provisioner
  # to select. Higher weights indicate higher priority when comparing provisioners.
  # Specifying no weight is equivalent to specifying a weight of 0.
  weight: 1
  limits:
    resources:
      cpu: '2k'
  labels:
    billing-team: default
    team: default
    type: karpenter
    
  # Do we want to apply some taints on the nodes ?  
  # taints:
  #   - key: karpenter
  #     value: 'true'
  #     effect: NoSchedule

  # Karpenter provides the ability to specify a few additional Kubelet args.
  # These are all optional and provide support for additional customization and use cases.
  kubeletConfiguration:
    containerRuntime: containerd
    maxPods: 110     
    systemReserved:
      cpu: '1'
      memory: 5Gi
      ephemeral-storage: 2Gi
{{ end }}
EOF

This creates a default provisioner and a node template that will be used by Karpenter to create EKS nodes.

    we have set dedicated labels, that can be used by Pods as nodeSelectors.
    We can add taints to the nodes so that workloads could need to tolerate those taints to be scheduled on Karpenter's nodes.
    We specify some requirements arround Instances types, capacity and architecture, each provisioner is heavilly customizable, you can find more informations in the documentation 

.
You can create many different Karpenter provisioners, and even make it default for every additional workloads by not specifying any taints.
You can also define priority between different provisioners, so that you can use in priority your nodes which benefits from AWS Reserved Instances prices... you can find more informations in the documentation 

    .

Add, Commit and push the code:

1
2
3
git add teams/team-riker/dev/templates/karpenter.yaml
git commit -m "Add Karpenter provisioner"
git push






fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git add teams/team-riker/dev/templates/karpenter.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git commit -m "Add Karpenter provisioner"
[main 5316019] Add Karpenter provisioner
 1 file changed, 86 insertions(+)
 create mode 100644 teams/team-riker/dev/templates/karpenter.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git push
Enumerating objects: 12, done.
Counting objects: 100% (12/12), done.
Delta compression using up to 8 threads
Compressing objects: 100% (7/7), done.
Writing objects: 100% (7/7), 1.63 KiB | 1.63 MiB/s, done.
Total 7 (delta 3), reused 0 (delta 0)
remote: Resolving deltas: 100% (3/3), completed with 3 local objects.
To github.com:fernandomullerjr/eks-blueprints-workloads.git
   7f10445..5316019  main -> main
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$





- No UI do Argo:

APP HEALTH
 Suspended
CURRENT SYNC STATUS
Synced
To main (5316019)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
feature: adding skiapp which uses alb
LAST SYNC RESULT
Sync OK
To 5316019
Succeeded 5 minutes ago (Thu Mar 02 2023 17:48:43 GMT-0300)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
Add Karpenter provisioner








This provisioner will now be used by Karpenter when deploying workloads assuming the nodeSelector to the labels we defined, wut we need to activate it through or Helm value karpenterInstanceProfile

For now, we should have no Karpenter nodes in our cluster. let's check this with our alias to list our nodes:

1
2
3
kubectl get nodes
# or :
#kubectl get nodes -L karpenter.sh/capacity-type -L topology.kubernetes.io/zone -L karpenter.sh/provisioner-name

NAME                                        STATUS   ROLES    AGE   VERSION                CAPACITY-TYPE   ZONE         PROVISIONER-NAME
ip-10-0-10-190.eu-west-1.compute.internal   Ready    <none>   14d   v1.21.12-eks-5308cf7                   eu-west-1a
ip-10-0-11-188.eu-west-1.compute.internal   Ready    <none>   14d   v1.21.12-eks-5308cf7                   eu-west-1b
ip-10-0-12-127.eu-west-1.compute.internal   Ready    <none>   14d   v1.21.12-eks-5308cf7                   eu-west-1c

We can see our actual Managed nodes groups, 1 in each AZ, and there should not be already nodes managed by Karpenter.

We need to scale our workload so that Karpenter can scale nodes.





TeamRole:~/environment/eks-blueprint $ kubectl get nodes
NAME                          STATUS   ROLES    AGE    VERSION
ip-10-0-10-26.ec2.internal    Ready    <none>   6h2m   v1.23.16-eks-48e63af
ip-10-0-11-201.ec2.internal   Ready    <none>   6h2m   v1.23.16-eks-48e63af
ip-10-0-12-133.ec2.internal   Ready    <none>   6h2m   v1.23.16-eks-48e63af
TeamRole:~/environment/eks-blueprint $ # or :
TeamRole:~/environment/eks-blueprint $ #kubectl get nodes -L karpenter.sh/capacity-type -L topology.kubernetes.io/zone -L karpenter.sh/provisioner-name
TeamRole:~/environment/eks-blueprint $ 












# Step 3: Watch Workload on Karpenter's nodes as part of Riker Application Team

    First, in the locals.tf in the workload_application.values.spec uncomment the karpenterInstanceProfile so that our workloads knows that we can use Karpenter, remember, we have configured our rollout.yaml to add Karpenter nodeSelector and toleration if this parameter exists.

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
  workload_application = {
    path               = "envs/dev"
    repo_url           = local.workload_repo
    add_on_application = false
    values = {
      labels = {
        env   = local.env
        myapp = "myvalue"
      }
      spec = {
        source = {
          repoURL        = local.workload_repo
        }
        blueprint                = "terraform"
        clusterName              = local.name
        karpenterInstanceProfile = "${local.name}-${local.node_group_name}" # Activate to enable Karpenter manifests (only if Karpenter add-on is enabled)
        env                      = local.env
      }
    }    
  }

    Apply the change

terraform apply --auto-approve

    Check the Karpenter provisioner

Once ArgoCD would have synchronized or change with the new parameter, we can check that the provisioner is created. Wait a little if you don't see yet the provisioners.

get the default provisioner:

1
kubectl get provisioner

NAME      AGE
default   8m33s






- Descomentando esta linha:

karpenterInstanceProfile = "${local.name}-${local.node_group_name}" # Activate to enable Karpenter manifests (only when Karpenter add-on will be enabled in the Karpenter module)




- Fazendo apply:




TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform apply --auto-approve
data.aws_availability_zones.available: Reading...
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Reading...
module.karpenter.aws_sqs_queue.this[0]: Refreshing state... [id=https://sqs.us-east-1.amazonaws.com/537174683150/Karpenter-eks-blueprint]
module.eks_blueprints.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_region.current: Reading...
module.karpenter.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Reading...
module.kubernetes_addons.data.aws_caller_identity.current: Reading...
module.eks_blueprints.data.aws_partition.current: Reading...
module.eks_blueprints.data.aws_partition.current: Read complete after 0s [id=aws]
module.kubernetes_addons.data.aws_region.current: Read complete after 0s [id=us-east-1]
module.kubernetes_addons.data.aws_partition.current: Read complete after 0s [id=aws]
module.karpenter.data.aws_partition.current: Reading...
module.vpc.aws_vpc.this[0]: Refreshing state... [id=vpc-057282f16854c617a]
module.karpenter.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.data.aws_region.current: Reading...
module.eks_blueprints.data.aws_region.current: Read complete after 0s [id=us-east-1]
data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_region.current: Reading...
module.kubernetes_addons.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.karpenter.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
data.aws_region.current: Read complete after 0s [id=us-east-1]
data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.karpenter.aws_cloudwatch_event_rule.this["instance_rebalance"]: Refreshing state... [id=KarpenterInstanceRebalance-20230302204541354200000004]
module.eks_blueprints.module.aws_eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.karpenter.aws_cloudwatch_event_rule.this["instance_state_change"]: Refreshing state... [id=KarpenterInstanceStateChange-20230302204541345000000001]
module.karpenter.aws_cloudwatch_event_rule.this["health_event"]: Refreshing state... [id=KarpenterHealthEvent-20230302204541353400000003]
module.karpenter.aws_cloudwatch_event_rule.this["spot_interupt"]: Refreshing state... [id=KarpenterSpotInterrupt-20230302204541345100000002]
module.eks_blueprints.data.aws_iam_session_context.current: Reading...
module.karpenter.data.aws_iam_policy_document.assume_role[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks_blueprints.module.aws_eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.karpenter.data.aws_iam_policy_document.assume_role[0]: Read complete after 0s [id=2560088296]
module.eks_blueprints.module.aws_eks.aws_iam_role.this[0]: Refreshing state... [id=eks-blueprint-cluster-role]
module.karpenter.aws_iam_role.this[0]: Refreshing state... [id=Karpenter-eks-blueprint-20230302204541355900000005]
data.aws_availability_zones.available: Read complete after 0s [id=us-east-1]
module.vpc.aws_eip.nat[0]: Refreshing state... [id=eipalloc-060f3c60df7202312]
module.karpenter.data.aws_iam_policy_document.queue[0]: Reading...
module.karpenter.data.aws_iam_policy_document.queue[0]: Read complete after 0s [id=183412477]
module.karpenter.aws_sqs_queue_policy.this[0]: Refreshing state... [id=https://sqs.us-east-1.amazonaws.com/537174683150/Karpenter-eks-blueprint]
data.aws_arn.queue: Reading...
data.aws_arn.queue: Read complete after 0s [id=arn:aws:sqs:us-east-1:537174683150:Karpenter-eks-blueprint]
module.kubernetes_addons.module.karpenter[0].data.aws_iam_policy_document.karpenter: Reading...
module.kubernetes_addons.module.karpenter[0].data.aws_iam_policy_document.karpenter: Read complete after 0s [id=3940261044]
module.kubernetes_addons.module.karpenter[0].data.aws_arn.queue[0]: Reading...
module.kubernetes_addons.module.karpenter[0].data.aws_arn.queue[0]: Read complete after 0s [id=arn:aws:sqs:us-east-1:537174683150:Karpenter-eks-blueprint]
module.eks_blueprints.data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Reading...
module.eks_blueprints.data.aws_iam_policy_document.eks_key: Read complete after 0s [id=1163348263]
module.eks_blueprints.module.kms[0].aws_kms_key.this: Refreshing state... [id=9e3ecf11-9c0b-4b17-9e01-a039a438bc64]
module.karpenter.aws_cloudwatch_event_target.this["health_event"]: Refreshing state... [id=KarpenterHealthEvent-20230302204541353400000003-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["instance_rebalance"]: Refreshing state... [id=KarpenterInstanceRebalance-20230302204541354200000004-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["instance_state_change"]: Refreshing state... [id=KarpenterInstanceStateChange-20230302204541345000000001-KarpenterInterruptionQueueTarget]
module.karpenter.aws_cloudwatch_event_target.this["spot_interupt"]: Refreshing state... [id=KarpenterSpotInterrupt-20230302204541345100000002-KarpenterInterruptionQueueTarget]
module.karpenter.aws_iam_instance_profile.this[0]: Refreshing state... [id=Karpenter-eks-blueprint-20230302204541730000000006]
module.karpenter.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=Karpenter-eks-blueprint-20230302204541355900000005-20230302204541825300000009]
module.karpenter.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=Karpenter-eks-blueprint-20230302204541355900000005-20230302204541814300000008]
module.karpenter.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=Karpenter-eks-blueprint-20230302204541355900000005-20230302204541795200000007]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426195300000001]
module.eks_blueprints.module.aws_eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Refreshing state... [id=eks-blueprint-cluster-role-20230302143426196900000002]
module.eks_blueprints.module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint]
module.eks_blueprints.module.aws_eks.aws_security_group.cluster[0]: Refreshing state... [id=sg-054686326d2114ed9]
module.vpc.aws_default_network_acl.this[0]: Refreshing state... [id=acl-048d848d0e3b85322]
module.vpc.aws_default_route_table.default[0]: Refreshing state... [id=rtb-092fea16a6047314e]
module.vpc.aws_route_table.public[0]: Refreshing state... [id=rtb-0b6d8c9155c8b9e9b]
module.vpc.aws_default_security_group.this[0]: Refreshing state... [id=sg-03a6402a6175a2c7f]
module.eks_blueprints.module.aws_eks.aws_security_group.node[0]: Refreshing state... [id=sg-01292be1fd85c73dc]
module.vpc.aws_route_table.private[0]: Refreshing state... [id=rtb-09be8403309ae0aa2]
module.vpc.aws_subnet.private[2]: Refreshing state... [id=subnet-0be0d519d8ebf571d]
module.vpc.aws_subnet.private[1]: Refreshing state... [id=subnet-001712d064ce30d0f]
module.vpc.aws_subnet.private[0]: Refreshing state... [id=subnet-003239cf34af36155]
module.vpc.aws_internet_gateway.this[0]: Refreshing state... [id=igw-012195b4861aff7ba]
module.vpc.aws_subnet.public[1]: Refreshing state... [id=subnet-0632179e892cad4d8]
module.vpc.aws_subnet.public[0]: Refreshing state... [id=subnet-00fdd4c825f59ce54]
module.vpc.aws_subnet.public[2]: Refreshing state... [id=subnet-0bde606efb46b66a9]
module.vpc.aws_route.public_internet_gateway[0]: Refreshing state... [id=r-rtb-0b6d8c9155c8b9e9b1080289494]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_https"]: Refreshing state... [id=sgrule-485308346]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1676664753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Refreshing state... [id=sgrule-3350232158]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_udp"]: Refreshing state... [id=sgrule-3182243753]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Refreshing state... [id=sgrule-3417284189]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Refreshing state... [id=sgrule-1170742331]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_443"]: Refreshing state... [id=sgrule-1057497985]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_cluster_443"]: Refreshing state... [id=sgrule-1760785725]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["egress_ntp_tcp"]: Refreshing state... [id=sgrule-3274902180]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Refreshing state... [id=sgrule-1025986205]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Refreshing state... [id=sgrule-1248790130]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Refreshing state... [id=sgrule-3729007676]
module.eks_blueprints.module.aws_eks.aws_security_group_rule.cluster["egress_nodes_443"]: Refreshing state... [id=sgrule-483936066]
module.vpc.aws_nat_gateway.this[0]: Refreshing state... [id=nat-0466dcddece341f3e]
module.vpc.aws_route_table_association.public[0]: Refreshing state... [id=rtbassoc-04515728675c019eb]
module.vpc.aws_route_table_association.public[1]: Refreshing state... [id=rtbassoc-02fb89647e4d2a1ff]
module.vpc.aws_route_table_association.public[2]: Refreshing state... [id=rtbassoc-0f5b6eebb1f4f0daf]
module.vpc.aws_route_table_association.private[1]: Refreshing state... [id=rtbassoc-0a43222e26d8b966c]
module.vpc.aws_route_table_association.private[0]: Refreshing state... [id=rtbassoc-03782f745452a836a]
module.vpc.aws_route_table_association.private[2]: Refreshing state... [id=rtbassoc-090f4e4ab159c1cba]
module.vpc.aws_route.private_nat_gateway[0]: Refreshing state... [id=r-rtb-09be8403309ae0aa21080289494]
module.eks_blueprints.module.aws_eks.aws_eks_cluster.this[0]: Refreshing state... [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Reading...
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]: Refreshing state... [id=sg-095f66c2dbe06af2f,GithubRepo]
module.eks_blueprints.module.aws_eks.aws_ec2_tag.cluster_primary_security_group["Blueprint"]: Refreshing state... [id=sg-095f66c2dbe06af2f,Blueprint]
data.aws_eks_cluster.cluster: Reading...
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Reading...
data.aws_eks_cluster_auth.this: Reading...
module.kubernetes_addons.time_sleep.dataplane: Refreshing state... [id=2023-03-02T18:42:45Z]
data.aws_eks_cluster_auth.this: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.data.tls_certificate.this[0]: Read complete after 0s [id=8cb781b6037f4703f17f42d8de4a2c2aa78474ab]
data.aws_eks_cluster.cluster: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.data.aws_eks_cluster.cluster[0]: Read complete after 0s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks.aws_iam_openid_connect_provider.oidc_provider[0]: Refreshing state... [id=arn:aws:iam::537174683150:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/9B6026EAB5E6A8F5691FAD12314E6672]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Reading...
module.kubernetes_addons.module.argo_rollouts[0].kubernetes_namespace_v1.this[0]: Refreshing state... [id=argo-rollouts]
module.kubernetes_addons.module.argocd[0].kubernetes_namespace_v1.this[0]: Refreshing state... [id=argocd]
module.eks_blueprints.data.http.eks_cluster_readiness[0]: Read complete after 0s [id=https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com/healthz]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Reading...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_region.current: Read complete after 0s [id=us-east-1]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks_blueprints.kubernetes_config_map.aws_auth[0]: Refreshing state... [id=kube-system/aws-auth]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_namespace.team["team-riker"]: Refreshing state... [id=team-riker]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_access["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-access]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_caller_identity.current: Read complete after 0s [id=537174683150]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_cluster_role_binding.team["team-riker"]: Refreshing state... [id=team-riker-team-cluster-role-binding]
module.kubernetes_addons.data.aws_eks_cluster.eks_cluster: Read complete after 0s [id=eks-blueprint]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_eks_cluster.eks_cluster: Read complete after 1s [id=eks-blueprint]
module.eks_blueprints.module.aws_eks_teams[0].kubectl_manifest.team["kubernetes/team-riker/limit-range.yaml"]: Refreshing state... [id=/api/v1/namespaces/team-riker/limitranges/resource-limits]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Refreshing state... [id=team-riker/quotas]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_iam_policy_document.aws_ebs_csi_driver[0]: Read complete after 0s [id=1888929143]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_role_binding.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-role-binding]
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Reading...
module.eks_blueprints.module.aws_eks_teams[0].data.aws_iam_policy_document.platform_team_eks_access[0]: Read complete after 0s [id=3353604467]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.irsa: Read complete after 0s [id=3161176853]
module.kubernetes_addons.module.karpenter[0].aws_iam_policy.karpenter: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-karpenter]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_iam_policy.aws_ebs_csi_driver[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-aws-ebs-csi-driver-irsa]
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Reading...
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_session_context.current: Read complete after 0s [id=arn:aws:sts::537174683150:assumed-role/mod-9bdf479182da404f-ExampleC9Role-G1OP707ZLE9D/i-077b187ba40c6ebba]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_policy.platform_team_eks_access[0]: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-PlatformTeamEKSAccess]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_iam_policy.aws_for_fluent_bit: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-fluentbit]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Reading...
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.team_sa_irsa["team-riker"]: Refreshing state... [id=eks-blueprint-team-riker-sa-role]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].data.aws_iam_policy_document.managed_ng_assume_role_policy: Read complete after 0s [id=3778018924]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Reading...
module.kubernetes_addons.module.aws_load_balancer_controller[0].data.aws_iam_policy_document.aws_lb: Read complete after 0s [id=2633998141]
module.kubernetes_addons.module.aws_for_fluent_bit[0].data.aws_iam_policy_document.kms: Read complete after 0s [id=1146648495]
module.kubernetes_addons.module.argocd[0].module.helm_addon.helm_release.addon[0]: Refreshing state... [id=argo-cd]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.kubernetes_addons.module.aws_load_balancer_controller[0].aws_iam_policy.aws_load_balancer_controller: Refreshing state... [id=arn:aws:iam::537174683150:policy/eks-blueprint-lb-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_key.this: Refreshing state... [id=3b6f2a5a-bdd3-4754-adcc-b129c04a00ff]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Refreshing state... [id=karpenter]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-karpenter-irsa]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].data.aws_eks_addon_version.this: Read complete after 1s [id=aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_namespace_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.kms[0].aws_kms_alias.this: Refreshing state... [id=alias/eks-blueprint-cw-fluent-bit]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548648800000008]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_instance_profile.managed_ng[0]: Refreshing state... [id=eks-blueprint-managed-ondemand]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548638600000006]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548720000000009]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_iam_role_policy_attachment.managed_ng["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Refreshing state... [id=eks-blueprint-managed-ondemand-20230302144548642900000007]
module.kubernetes_addons.module.aws_for_fluent_bit[0].aws_cloudwatch_log_group.aws_for_fluent_bit[0]: Refreshing state... [id=/eks-blueprint/worker-fluentbit-logs]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=karpenter/karpenter]
module.kubernetes_addons.module.karpenter[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-karpenter-irsa-2023030220460746410000000a]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].module.irsa_addon[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-ebs-csi-controller-sa-irsa-20230302184246481600000003]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa]
module.kubernetes_addons.module.aws_ebs_csi_driver[0].aws_eks_addon.aws_ebs_csi_driver[0]: Refreshing state... [id=eks-blueprint:aws-ebs-csi-driver]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-for-fluent-bit-sa-irsa-20230302184246496400000004]
module.kubernetes_addons.module.aws_for_fluent_bit[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=aws-for-fluent-bit/aws-for-fluent-bit-sa]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].aws_iam_role_policy_attachment.irsa[0]: Refreshing state... [id=eks-blueprint-aws-load-balancer-controller-sa-irsa-20230302184246481500000002]
module.kubernetes_addons.module.aws_load_balancer_controller[0].module.helm_addon.module.irsa[0].kubernetes_service_account_v1.irsa[0]: Refreshing state... [id=kube-system/aws-load-balancer-controller-sa]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Refreshing state... [id=addons]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Refreshing state... [id=workloads]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"] will be updated in-place
  ~ resource "helm_release" "argocd_application" {
        id                         = "workloads"
        name                       = "workloads"
        # (27 unchanged attributes hidden)

      + set {
          + name  = "source.helm.values"
          + type  = "auto"
          + value = <<-EOT
                "account": "537174683150"
                "clusterName": "eks-blueprint"
                "labels":
                  "env": "dev"
                  "myapp": "myvalue"
                "region": "us-east-1"
                "repoUrl": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
                "spec":
                  "blueprint": "terraform"
                  "clusterName": "eks-blueprint"
                  "env": "dev"
                  "karpenterInstanceProfile": "eks-blueprint-managed-ondemand"
                  "source":
                    "repoURL": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
            EOT
        }
      - set {
          - name  = "source.helm.values" -> null
          - type  = "auto" -> null
          - value = <<-EOT
                "account": "537174683150"
                "clusterName": "eks-blueprint"
                "labels":
                  "env": "dev"
                  "myapp": "myvalue"
                "region": "us-east-1"
                "repoUrl": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
                "spec":
                  "blueprint": "terraform"
                  "clusterName": "eks-blueprint"
                  "env": "dev"
                  "source":
                    "repoURL": "https://github.com/fernandomullerjr/eks-blueprints-workloads.git"
            EOT -> null
        }

        # (7 unchanged blocks hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Modifying... [id=workloads]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Modifications complete after 2s [id=workloads]

Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 







- Na UI do Argo
 Applications
team-rike

provisioner tá sendo deployado



TeamRole:~/environment/eks-blueprint $ kubectl get provisioner

NAME      AGE
burnham   65s
default   75s
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 











#     Promote our rollout

As Terraform is injecting a new value to the Rollout deployment, ArgoCD is going to deploy a new revision of the application. We can watch it either in the Argo Rollout Dashboard, or with the cli

# list the rollout
kubectl argo rollouts list rollouts -n team-riker
# Get detail on our ski-app rollouts
kubectl argo rollouts get rollout skiapp-rollout -n team-riker -w
# Promote the rollout
kubectl argo rollouts promote skiapp-rollout -n team-riker






TeamRole:~/environment/eks-blueprint $ 
Name:            skiapp-rollout
Namespace:       team-riker
Status:          ◌ Progressing
Message:         active service cutover pending
Strategy:        BlueGreen
Images:          sharepointoscar/skiapp:v1 (stable, active)
                 sharepointoscar/skiapp:v2 (preview)
Replicas:
  Desired:       3
  Current:       6
  Updated:       3
  Ready:         3
  Available:     3

NAME                                        KIND        STATUS               AGE   INFO
⟳ skiapp-rollout                            Rollout     ◌ Progressing        37m   
├──# revision:3                                                                    
│  └──⧉ skiapp-rollout-6dc79589d9           ReplicaSet  ◌ Progressing        2m3s  preview
│     ├──□ skiapp-rollout-6dc79589d9-87nfj  Pod         ✔ Running            2m3s  ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-t7vfb  Pod         ◌ ContainerCreating  2m3s  ready:0/1
│     └──□ skiapp-rollout-6dc79589d9-m9qhp  Pod         ✔ Running            86s   ready:1/1
├──# revision:2                                                                    
│  └──⧉ skiapp-rollout-6c6d4bf568           ReplicaSet  • ScaledDown         28m   
└──# revision:1                                                                    
   └──⧉ skiapp-rollout-7cddc49665           ReplicaSet  ✔ Healthy            37m   stable,active
      ├──□ skiapp-rollout-7cddc49665-95lcc  Pod         ✔ Running            37m   ready:1/1
      ├──□ skiapp-rollout-7cddc49665-mp6v4  Pod         ✔ Running            37m   ready:1/1
      └──□ skiapp-rollout-7cddc49665-qr972  Pod         ✔ Running            37m   ready:1/1
^CTeamRole:~/environment/eks-blueprint $ kubectl argo rollouts promote skiapp-rollout -n team-riker
rollout 'skiapp-rollout' promoted
TeamRole:~/environment/eks-blueprint $ kubectl argo rollouts list rollouts -n team-riker
NAME            STRATEGY   STATUS        STEP  SET-WEIGHT  READY  DESIRED  UP-TO-DATE  AVAILABLE
skiapp-rollout  BlueGreen  Progressing   -     -           3/6    3        3           3        
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 














By promoting the new App this should leave only 3 pods for our application, and thoses pods should now be deployed on Karpenter instances.

    We are going to use a tool to dynamically see the nodes in our cluster : eks-node-viewer 

    . Open another terminal and execute:

1
eks-node-viewer -extra-labels karpenter.sh/provisioner-name,topology.kubernetes.io/zone

    Scale the Rollout manually so that we have 2 pods on each instance, one in each availability zone

Important
Before scaling, delete the 2048 app from your workload repository, so that we can focus on 1 app and see the scaling behaviour.

1
kubectl scale rollout -n team-riker skiapp-rollout --replicas 6



TeamRole:~/environment/eks-blueprint $ eks-node-viewer -extra-labels karpenter.sh/provisioner-name,topology.kubernetes.io/zone
bash: eks-node-viewer: command not found
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ kubectl scale rollout -n team-riker skiapp-rollout --replicas 6

rollout.argoproj.io/skiapp-rollout scaled
TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ 



# PENDENTE
- Ver sobre ferramenta eks-node-viewer




# eks-node-viewer
Installation

Please either fetch the latest release or install manually using:

go install github.com/awslabs/eks-node-viewer/cmd/eks-node-viewer@latest










Important
This tool has actually a bug on linux that prevent correctly refhreshing the number of pods, you can stop/restart it to be sure to reflect actual situation.

    Now scale to 14

1
kubectl scale rollout -n team-riker skiapp-rollout --replicas 14

What happened ?

    In first place, it add 3 bigger instances, one in each zone to fullfill our requirements.
    In a second time, we can see that the Karpenter consolidation activated, and that it has removed the 3 smaller nodes, and move their pods on the bigger instance. This in the goal of saving costs.








kubectl scale rollout -n team-riker skiapp-rollout --replicas 14

TeamRole:~/environment/eks-blueprint $ kubectl scale rollout -n team-riker skiapp-rollout --replicas 14
rollout.argoproj.io/skiapp-rollout scaled
TeamRole:~/environment/eks-blueprint $ kubectl argo rollouts list rollouts -n team-riker
NAME            STRATEGY   STATUS        STEP  SET-WEIGHT  READY  DESIRED  UP-TO-DATE  AVAILABLE
skiapp-rollout  BlueGreen  Progressing   -     -           6/11   14       5           6        
TeamRole:~/environment/eks-blueprint $ 



eks-node-viewer -extra-labels karpenter.sh/provisioner-name,topology.kubernetes.io/zone

9 nodes (8715m/18340m) 47.5% cpu ███████████████████░░░░░░░░░░░░░░░░░░░░░ $0.986/hour | $719.780/month 
91 pods (0 pending 91 running 91 bound)

ip-10-0-12-133.ec2.internal cpu █████████░░░░░░░░░░░░░░░░░░░░░░░░░░  25% (19 pods) m5.xlarge/$0.192 On-Demand - Ready         us-east-1c 
ip-10-0-11-201.ec2.internal cpu ████████████████░░░░░░░░░░░░░░░░░░░  45% (19 pods) m5.xlarge/$0.192 On-Demand - Ready         us-east-1b 
ip-10-0-10-26.ec2.internal  cpu ██████████████████░░░░░░░░░░░░░░░░░  51% (18 pods) m5.xlarge/$0.192 On-Demand - Ready         us-east-1a 
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034 Spot      - Ready burnham us-east-1a 
ip-10-0-10-237.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1a 
ip-10-0-11-176.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1b 
ip-10-0-11-207.ec2.internal cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (5 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1b 
ip-10-0-12-177.ec2.internal cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (5 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1c 
ip-10-0-12-229.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1c 
Press any key to quit











kubectl scale rollout -n team-riker skiapp-rollout --replicas 25



- Não está atualizando o número de Nodes e Pods:

eks-node-viewer -extra-labels karpenter.sh/provisioner-name,topology.kubernetes.io/zone

9 nodes (8715m/18340m) 47.5% cpu ███████████████████░░░░░░░░░░░░░░░░░░░░░ $0.986/hour | $719.780/month 
91 pods (0 pending 91 running 91 bound)

ip-10-0-12-133.ec2.internal cpu █████████░░░░░░░░░░░░░░░░░░░░░░░░░░  25% (19 pods) m5.xlarge/$0.192 On-Demand - Ready         us-east-1c 
ip-10-0-11-201.ec2.internal cpu ████████████████░░░░░░░░░░░░░░░░░░░  45% (19 pods) m5.xlarge/$0.192 On-Demand - Ready         us-east-1b 
ip-10-0-10-26.ec2.internal  cpu ██████████████████░░░░░░░░░░░░░░░░░  51% (18 pods) m5.xlarge/$0.192 On-Demand - Ready         us-east-1a 
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034 Spot      - Ready burnham us-east-1a 
ip-10-0-10-237.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1a 
ip-10-0-11-176.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1b 
ip-10-0-11-207.ec2.internal cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (5 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1b 
ip-10-0-12-177.ec2.internal cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (5 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1c 
ip-10-0-12-229.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075 On-Demand - Ready default us-east-1c 
Press any key to quit






# What happened ?

    In first place, it add 3 bigger instances, one in each zone to fullfill our requirements.
    In a second time, we can see that the Karpenter consolidation activated, and that it has removed the 3 smaller nodes, and move their pods on the bigger instance. This in the goal of saving costs.

    Now scale to 20

1
kubectl scale rollout -n team-riker skiapp-rollout --replicas 20

What happened ?

    Nothing

Why ?

    We have reach the namespace quotas for the number of pods

    k get quota -n team-riker

    You can increase the quotas by upgrading the values in main.tf and deploying again

      application_teams = {
        team-riker = {
          "labels" = {
            "appName"     = "riker-team-app",
            "projectName" = "project-riker",
            "environment" = "dev",
            "domain"      = "example",
            "uuid"        = "example",
            "billingCode" = "example",
            "branch"      = "example"
          }
          "quota" = {
            "requests.cpu"    = "10",
            "requests.memory" = "20Gi",
            "limits.cpu"      = "30",
            "limits.memory"   = "50Gi",
            "pods"            = "30", #<-- increase value>
            "secrets"         = "10",
            "services"        = "10"
          }
          ## Manifests Example: we can specify a directory with kubernetes manifests that can be automatically applied in the team-riker namespace.
          manifests_dir = "./kubernetes/team-riker"
          users         = [data.aws_caller_identity.current.arn]
        }

    After some times you should be able to have all pods deployed




- Atual:

TeamRole:~/environment/eks-blueprint $ k get quota -n team-riker
NAME     AGE    REQUEST                                                                                           LIMIT
quotas   3h6m   pods: 15/15, requests.cpu: 3550m/10, requests.memory: 904Mi/20Gi, secrets: 2/10, services: 4/10   limits.cpu: 7050m/30, limits.memory: 2994Mi/50Gi
TeamRole:~/environment/eks-blueprint $ 




- Ajustando as quotas:

      "quota" = {
        "requests.cpu"    = "30",
        "requests.memory" = "60Gi",
        "limits.cpu"      = "80",
        "limits.memory"   = "80Gi",
        "pods"            = "45",
        "secrets"         = "30",
        "services"        = "30"
      }


# Always a good practice to use a dry-run command
terraform plan

1
2
# apply changes to provision the Platform Team
terraform apply -auto-approve




TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform plan
data.aws_region.current: Reading...
module.kubernetes_addons.data.aws_region.current: Reading...
data.aws_region.current: Read complete after 0s [id=us-east-1]
[............................................]
module.eks_blueprints.module.aws_eks_teams[0].aws_iam_role.platform_team["admin"]: Refreshing state... [id=eks-blueprint-admin-access]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_service_account.team["team-riker"]: Refreshing state... [id=team-riker/team-riker-sa]
module.eks_blueprints.module.aws_eks_managed_node_groups["mg_5"].aws_eks_node_group.managed_ng: Refreshing state... [id=eks-blueprint:managed-ondemand-2023030214454877610000000a]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Refreshing state... [id=addons]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["workloads"]: Refreshing state... [id=workloads]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"] will be updated in-place
  ~ resource "kubernetes_resource_quota" "this" {
        id = "team-riker/quotas"

      ~ spec {
          ~ hard   = {
              ~ "limits.cpu"      = "30" -> "80"
              ~ "limits.memory"   = "50Gi" -> "80Gi"
              ~ "pods"            = "15" -> "45"
              ~ "requests.cpu"    = "10" -> "30"
              ~ "requests.memory" = "20Gi" -> "60Gi"
              ~ "secrets"         = "10" -> "30"
              ~ "services"        = "10" -> "30"
            }
            # (1 unchanged attribute hidden)
        }

        # (1 unchanged block hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't guarantee to take exactly these actions if you run "terraform apply" now.
TeamRole:~/environment/eks-blueprint $ 




- Apply


Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"] will be updated in-place
  ~ resource "kubernetes_resource_quota" "this" {
        id = "team-riker/quotas"

      ~ spec {
          ~ hard   = {
              ~ "limits.cpu"      = "30" -> "80"
              ~ "limits.memory"   = "50Gi" -> "80Gi"
              ~ "pods"            = "15" -> "45"
              ~ "requests.cpu"    = "10" -> "30"
              ~ "requests.memory" = "20Gi" -> "60Gi"
              ~ "secrets"         = "10" -> "30"
              ~ "services"        = "10" -> "30"
            }
            # (1 unchanged attribute hidden)
        }

        # (1 unchanged block hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Modifying... [id=team-riker/quotas]
module.eks_blueprints.module.aws_eks_teams[0].kubernetes_resource_quota.this["team-riker"]: Modifications complete after 0s [id=team-riker/quotas]

Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 






TeamRole:~/environment/eks-blueprint $ k get quota -n team-riker
NAME     AGE     REQUEST                                                                                           LIMIT
quotas   3h10m   pods: 15/45, requests.cpu: 3550m/30, requests.memory: 904Mi/60Gi, secrets: 2/30, services: 4/30   limits.cpu: 7050m/80, limits.memory: 2994Mi/80Gi
TeamRole:~/environment/eks-blueprint $ 



- Após o ajuste nas quotas, scale do Rollout criou os Pods esperados:

kubectl scale rollout -n team-riker skiapp-rollout --replicas 12






11 nodes (11875m/22190m) 53.5% cpu █████████████████████░░░░░░░░░░░░░░░░░░░ $1.212/hour | $884.468/month 
110 pods (0 pending 110 running 110 bound)

ip-10-0-12-133.ec2.internal cpu █████████████░░░░░░░░░░░░░░░░░░░░░░  37% (21 pods) m5.xlarge/$0.192  On-Demand - Ready         us-east-1c 
ip-10-0-11-201.ec2.internal cpu ██████████████████░░░░░░░░░░░░░░░░░  51% (20 pods) m5.xlarge/$0.192  On-Demand - Ready         us-east-1b 
ip-10-0-10-26.ec2.internal  cpu █████████████████████████░░░░░░░░░░  70% (21 pods) m5.xlarge/$0.192  On-Demand - Ready         us-east-1a 
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034  Spot      - Ready burnham us-east-1a 
ip-10-0-11-176.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand - Ready default us-east-1b 
ip-10-0-11-207.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand - Ready default us-east-1b 
ip-10-0-12-177.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand - Ready default us-east-1c 
ip-10-0-12-229.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand - Ready default us-east-1c 
ip-10-0-11-81.ec2.internal  cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand - Ready default us-east-1b 
ip-10-0-10-218.ec2.internal cpu ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░  24% (6 pods)  t3a.xlarge/$0.150 On-Demand - Ready default us-east-1a 
ip-10-0-12-171.ec2.internal cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (5 pods)  t3a.large/$0.075  On-Demand - Ready default us-east-1c 
Press any key to quit







TeamRole:~/environment/eks-blueprint $ kubectl argo rollouts list rollouts -n team-riker
NAME            STRATEGY   STATUS        STEP  SET-WEIGHT  READY  DESIRED  UP-TO-DATE  AVAILABLE
skiapp-rollout  BlueGreen  Paused        -     -           12/24  12       12          12       
TeamRole:~/environment/eks-blueprint $ 



NAME                                        KIND        STATUS         AGE    INFO
⟳ skiapp-rollout                            Rollout     ॥ Paused       56m    
├──# revision:3                                                               
│  └──⧉ skiapp-rollout-6dc79589d9           ReplicaSet  ◌ Progressing  21m    preview
│     ├──□ skiapp-rollout-6dc79589d9-kppjf  Pod         ✔ Running      18m    ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-n86qz  Pod         ✔ Running      17m    ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-gbkbj  Pod         ✔ Running      17m    ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-cjmgk  Pod         ✔ Running      14m    ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-l42wk  Pod         ✔ Running      2m24s  ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-599mf  Pod         ✔ Running      2m23s  ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-c7lz2  Pod         ✔ Running      2m23s  ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-dffd9  Pod         ✔ Running      2m23s  ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-l225r  Pod         ✔ Running      2m23s  ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-qfmvh  Pod         ✔ Running      2m23s  ready:1/1
│     ├──□ skiapp-rollout-6dc79589d9-txd5n  Pod         ✔ Running      48s    ready:1/1
│     └──□ skiapp-rollout-6dc79589d9-hlcr4  Pod         ◌ Pending      16s    ready:0/1
├──# revision:2                                                               
│  └──⧉ skiapp-rollout-6c6d4bf568           ReplicaSet  • ScaledDown   47m    
└──# revision:1                                                               
   └──⧉ skiapp-rollout-7cddc49665           ReplicaSet  ✔ Healthy      56m    stable,active
      ├──□ skiapp-rollout-7cddc49665-95lcc  Pod         ✔ Running      56m    ready:1/1
      ├──□ skiapp-rollout-7cddc49665-mp6v4  Pod         ✔ Running      56m    ready:1/1
      ├──□ skiapp-rollout-7cddc49665-qr972  Pod         ✔ Running      56m    ready:1/1
      ├──□ skiapp-rollout-7cddc49665-nkh8b  Pod         ✔ Running      17m    ready:1/1
      ├──□ skiapp-rollout-7cddc49665-nr5m8  Pod         ✔ Running      17m    ready:1/1
      ├──□ skiapp-rollout-7cddc49665-qtzh4  Pod         ✔ Running      17m    ready:1/1
      ├──□ skiapp-rollout-7cddc49665-25jfd  Pod         ✔ Running      2m24s  ready:1/1
      ├──□ skiapp-rollout-7cddc49665-cg4x7  Pod         ✔ Running      2m23s  ready:1/1
      ├──□ skiapp-rollout-7cddc49665-hnsp4  Pod         ✔ Running      2m23s  ready:1/1
      ├──□ skiapp-rollout-7cddc49665-jhrlj  Pod         ✔ Running      2m23s  ready:1/1
      ├──□ skiapp-rollout-7cddc49665-ssvf4  Pod         ✔ Running      2m23s  ready:1/1
      └──□ skiapp-rollout-7cddc49665-ts7zk  Pod         ✔ Running      2m23s  ready:1/1
^CTeamRole:~/environment/eks-blueprint $ 





- Escalando novamente:
kubectl scale rollout -n team-riker skiapp-rollout --replicas 19

kubectl scale rollout -n team-riker skiapp-rollout --replicas 19

Escalou e subiu mais nodes

13 nodes (16285m/28030m) 58.1% cpu ███████████████████████░░░░░░░░░░░░░░░░░ $1.512/hour | $1104.052/month 
134 pods (2 pending 132 running 134 bound)

ip-10-0-12-133.ec2.internal cpu ██████████████████████░░░░░░░░░░░░░  63% (25 pods) m5.xlarge/$0.192  On-Demand -        Ready         us-east-1c 
ip-10-0-11-201.ec2.internal cpu █████████████████████████░░░░░░░░░░  71% (23 pods) m5.xlarge/$0.192  On-Demand -        Ready         us-east-1b 
ip-10-0-10-26.ec2.internal  cpu █████████████████████████░░░░░░░░░░  70% (21 pods) m5.xlarge/$0.192  On-Demand -        Ready         us-east-1a 
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034  Spot      -        Ready burnham us-east-1a 
ip-10-0-11-176.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand Cordoned Ready default us-east-1b 
ip-10-0-11-207.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand Cordoned Ready default us-east-1b 
ip-10-0-12-177.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand Cordoned Ready default us-east-1c 
ip-10-0-12-229.ec2.internal cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand Cordoned Ready default us-east-1c 
ip-10-0-11-81.ec2.internal  cpu ███████████████████████████░░░░░░░░  76% (6 pods)  t3a.large/$0.075  On-Demand Cordoned Ready default us-east-1b 
ip-10-0-10-218.ec2.internal cpu █████████████████████████████░░░░░░  84% (13 pods) t3a.xlarge/$0.150 On-Demand -        Ready default us-east-1a 
ip-10-0-12-204.ec2.internal cpu ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░  24% (6 pods)  t3a.xlarge/$0.150 On-Demand -        Ready default us-east-1c 
ip-10-0-11-112.ec2.internal cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (5 pods)  t3a.large/$0.075  On-Demand -        Ready default us-east-1b 
ip-10-0-11-90.ec2.internal  cpu ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   7% (4 pods)  t3a.xlarge/$0.150 On-Demand -        Ready default us-east-1b 
Press any key to quit



















# Step 4: Improve cluster cost by fine-tuning our application

We have the ability to indefinitely add more capacity to our cluster in order to scale our workloads, and Karpenter ensures an optimal balance between instances and cost. However, is that sufficient to meet our needs?
Install KubeCost

Kubecost provides real-time cost visibility and insights for teams using Kubernetes, helping you continuously reduce your cloud costs. Amazon EKS supports Kubecost, which you can use to monitor your costs broken down by Kubernetes resources including pods, nodes, namespaces, and labels.

Go back to your main.tf and enable the kubecost add-on and redeploy your terraform:

  enable_kubecost                    = true

Enable the port-forward so that we can access the Kubecost UI:

kubectl port-forward --namespace kubecost deployment/kubecost-cost-analyzer 8081:9090

    Access the Tools -> Preview -> Preview Running Application This should gives you access to the Argo Rollout UI like previously.
    Update the URL and change the port to 8081 something like : https://5a8d28af62e9477f947403a7b4f81ecf.vfs.cloud9.eu-west-1.amazonaws.com:8081/ 

    You should have access to the KubeCost UI

We know want to see if we can optimize our skiapp workload:

    Click on Savings in the left menu
    Click on Right-size your container requests
    We can see a table where there is some recommendations like in the following




# Always a good practice to use a dry-run command
terraform plan

1
2
# apply changes to provision the Platform Team
terraform apply -auto-approve




Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"] will be updated in-place
  ~ resource "helm_release" "argocd_application" {
        id                         = "addons"
        name                       = "addons"
        # (27 unchanged attributes hidden)

      + set {
          + name  = "source.helm.values"
          + type  = "auto"
          + value = <<-EOT
                "account": "537174683150"
                "argoRollouts":
                  "enable": "true"
                "awsForFluentBit":
                  "enable": "true"
                  "logGroupName": "/eks-blueprint/worker-fluentbit-logs"
                  "serviceAccountName": "aws-for-fluent-bit-sa"
                "awsLoadBalancerController":
                  "enable": "true"
                  "serviceAccountName": "aws-load-balancer-controller-sa"
                "clusterName": "eks-blueprint"
                "karpenter":
                  "awsDefaultInstanceProfile": "Karpenter-eks-blueprint-20230302204541730000000006"
                  "controllerClusterEndpoint": "https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com"
                  "enable": "true"
                  "serviceAccountName": "karpenter"
                "kubecost":
                  "enable": "true"
                "metricsServer":
                  "enable": "true"
                "region": "us-east-1"
                "repoUrl": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
            EOT
        }
      - set {
          - name  = "source.helm.values" -> null
          - type  = "auto" -> null
          - value = <<-EOT
                "account": "537174683150"
                "argoRollouts":
                  "enable": "true"
                "awsForFluentBit":
                  "enable": "true"
                  "logGroupName": "/eks-blueprint/worker-fluentbit-logs"
                  "serviceAccountName": "aws-for-fluent-bit-sa"
                "awsLoadBalancerController":
                  "enable": "true"
                  "serviceAccountName": "aws-load-balancer-controller-sa"
                "clusterName": "eks-blueprint"
                "karpenter":
                  "awsDefaultInstanceProfile": "Karpenter-eks-blueprint-20230302204541730000000006"
                  "controllerClusterEndpoint": "https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com"
                  "enable": "true"
                  "serviceAccountName": "karpenter"
                "metricsServer":
                  "enable": "true"
                "region": "us-east-1"
                "repoUrl": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
            EOT -> null
        }

        # (7 unchanged blocks hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't guarantee to take exactly these actions if you run "terraform apply" now.
TeamRole:~/environment/eks-blueprint $ 






Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"] will be updated in-place
  ~ resource "helm_release" "argocd_application" {
        id                         = "addons"
        name                       = "addons"
        # (27 unchanged attributes hidden)

      + set {
          + name  = "source.helm.values"
          + type  = "auto"
          + value = <<-EOT
                "account": "537174683150"
                "argoRollouts":
                  "enable": "true"
                "awsForFluentBit":
                  "enable": "true"
                  "logGroupName": "/eks-blueprint/worker-fluentbit-logs"
                  "serviceAccountName": "aws-for-fluent-bit-sa"
                "awsLoadBalancerController":
                  "enable": "true"
                  "serviceAccountName": "aws-load-balancer-controller-sa"
                "clusterName": "eks-blueprint"
                "karpenter":
                  "awsDefaultInstanceProfile": "Karpenter-eks-blueprint-20230302204541730000000006"
                  "controllerClusterEndpoint": "https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com"
                  "enable": "true"
                  "serviceAccountName": "karpenter"
                "kubecost":
                  "enable": "true"
                "metricsServer":
                  "enable": "true"
                "region": "us-east-1"
                "repoUrl": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
            EOT
        }
      - set {
          - name  = "source.helm.values" -> null
          - type  = "auto" -> null
          - value = <<-EOT
                "account": "537174683150"
                "argoRollouts":
                  "enable": "true"
                "awsForFluentBit":
                  "enable": "true"
                  "logGroupName": "/eks-blueprint/worker-fluentbit-logs"
                  "serviceAccountName": "aws-for-fluent-bit-sa"
                "awsLoadBalancerController":
                  "enable": "true"
                  "serviceAccountName": "aws-load-balancer-controller-sa"
                "clusterName": "eks-blueprint"
                "karpenter":
                  "awsDefaultInstanceProfile": "Karpenter-eks-blueprint-20230302204541730000000006"
                  "controllerClusterEndpoint": "https://9B6026EAB5E6A8F5691FAD12314E6672.yl4.us-east-1.eks.amazonaws.com"
                  "enable": "true"
                  "serviceAccountName": "karpenter"
                "metricsServer":
                  "enable": "true"
                "region": "us-east-1"
                "repoUrl": "https://github.com/aws-samples/eks-blueprints-add-ons.git"
            EOT -> null
        }

        # (7 unchanged blocks hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifying... [id=addons]
module.kubernetes_addons.module.argocd[0].helm_release.argocd_application["addons"]: Modifications complete after 1s [id=addons]

Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

Outputs:

application_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-team-riker-access"
configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint"
platform_teams_configure_kubectl = "aws eks --region us-east-1 update-kubeconfig --name eks-blueprint  --role-arn arn:aws:iam::537174683150:role/eks-blueprint-admin-access"
vpc_id = "vpc-057282f16854c617a"
TeamRole:~/environment/eks-blueprint $ 



Enable the port-forward so that we can access the Kubecost UI:

kubectl port-forward --namespace kubecost deployment/kubecost-cost-analyzer 8081:9090


TeamRole:~/environment/eks-blueprint $ kubectl port-forward --namespace kubecost deployment/kubecost-cost-analyzer 8081:9090
Forwarding from 127.0.0.1:8081 -> 9090
Forwarding from [::1]:8081 -> 9090




Access the Tools -> Preview -> Preview Running Application This should gives you access to the Argo Rollout UI like previously.
Update the URL and change the port to 8081 something like : https://5a8d28af62e9477f947403a7b4f81ecf.vfs.cloud9.eu-west-1.amazonaws.com:8081/ 

    You should have access to the KubeCost UI

We know want to see if we can optimize our skiapp workload:

    Click on Savings in the left menu
    Click on Right-size your container requests
    We can see a table where there is some recommendations like in the following

Traz o detalhamento de Pods, Limits setados e indicados.





With that, go back to your workload definition repository in codespace, and:

    edit the rollout.yaml file to change our pods ressources
    update the replicas with the las one we had (20)

Important
As we have updated the number of replicas from the cli, also put back the number of replicas in the file

1
2
3
4
5
6
7
8
9
10
11
12
apiVersion: argoproj.io/v1alpha1
kind: Rollout
...
spec:
  replicas: 20
...
          requests:
              memory: "64Mi"
              cpu: "50m"
          limits:
              memory: "128Mi"
              cpu: "100m"  

    Commit and push your changes, and let ArgoCD synchronise it with the cluster What happened ?

    A New Rollout changed has been staged in preview
    each of the replicaset has reach the number of 20 replicas, so they are ready to get production requests.

    Promote the new version

    kubectl argo rollouts promote skiapp-rollout -n team-riker




- Ajustada a quantidade de Replicas:


fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git status
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        modified:   teams/team-riker/dev/templates/alb-skiapp/rollout.yaml

no changes added to commit (use "git add" and/or "git commit -a")
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$

fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git add teams/team-riker/dev/templates/alb-skiapp/rollout.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git commit -m "Ajustado o rollout, replicas 20."
[main 967bc3a] Ajustado o rollout, replicas 20.
 1 file changed, 1 insertion(+), 1 deletion(-)
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git push
Enumerating objects: 15, done.
Counting objects: 100% (15/15), done.
Delta compression using up to 8 threads
Compressing objects: 100% (8/8), done.
Writing objects: 100% (8/8), 760 bytes | 760.00 KiB/s, done.
Total 8 (delta 4), reused 0 (delta 0)
remote: Resolving deltas: 100% (4/4), completed with 4 local objects.
To github.com:fernandomullerjr/eks-blueprints-workloads.git
   5316019..967bc3a  main -> main
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$








Promote the new version

kubectl argo rollouts promote skiapp-rollout -n team-riker


TeamRole:~/environment/eks-blueprint $ kubectl argo rollouts promote skiapp-rollout -n team-riker
rollout 'skiapp-rollout' promoted
TeamRole:~/environment/eks-blueprint $ 







    Karpenter consolidation will start, as new pods needs less ressources with the new configuration

    after some times, all the nodes should have changed to lower price ones.

Important
In our configuration we limited the EC2 instances category to be 'm' and 'c', but without this limitation Karpenter could even choose cheaper instances.

















# Step 5: Improve cluster cost by leveraging EC2 Spot Instances

Update EKS Blueprint to handle more Karpenter configuration
Important
At this point, we need to merge this PR 
in the official EKS Blueprint in order to allow us to pass the AWS SQS queue arn used to handle Spot Interruption.

While this is not yet included in EKS releases we will update our configuration to use my Fork. Execute this in your cloud9

1
sed -i 's#source = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.21.0/modules/kubernetes-addons"#source = "github.com/allamand/terraform-aws-eks-blueprints?ref=karpenter/modules/kubernetes-addons"#g' main.tf 

or manually change main.tf

module "kubernetes_addons" {
  source = "github.com/allamand/terraform-aws-eks-blueprints?ref=karpenter/modules/kubernetes-addons" #<- update the source >

  eks_cluster_id     = module.eks_blueprints.eks_cluster_id

Then we need to apply this changes:

terraform init && terraform apply --auto-approve"




- Fiz via sed

sed -i 's#source = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.21.0/modules/kubernetes-addons"#source = "github.com/allamand/terraform-aws-eks-blueprints?ref=karpenter/modules/kubernetes-addons"#g' main.tf



- Efetuando apply


- Erro:


TeamRole:~/environment/eks-blueprint $ 
TeamRole:~/environment/eks-blueprint $ terraform init && terraform apply --auto-approve
Initializing modules...
Downloading git::https://github.com/allamand/terraform-aws-eks-blueprints.git?ref=karpenter for kubernetes_addons...
╷
│ Error: Failed to download module
│ 
│ Could not download module "kubernetes_addons" (main.tf:128) source code from
│ "git::https://github.com/allamand/terraform-aws-eks-blueprints.git?ref=karpenter": error downloading
│ 'https://github.com/allamand/terraform-aws-eks-blueprints.git?ref=karpenter': /usr/bin/git exited with
│ 1: error: pathspec 'karpenter' did not match any file(s) known to git
│ 
╵

╷
│ Error: Failed to download module
│ 
│ Could not download module "kubernetes_addons" (main.tf:128) source code from
│ "git::https://github.com/allamand/terraform-aws-eks-blueprints.git?ref=karpenter": error downloading
│ 'https://github.com/allamand/terraform-aws-eks-blueprints.git?ref=karpenter': /usr/bin/git exited with
│ 1: error: pathspec 'karpenter' did not match any file(s) known to git
│ 
╵

╷
│ Error: Failed to download module
│ 
│ Could not download module "kubernetes_addons" (main.tf:128) source code from
│ "git::https://github.com/allamand/terraform-aws-eks-blueprints.git?ref=karpenter": error downloading
│ 'https://github.com/allamand/terraform-aws-eks-blueprints.git?ref=karpenter': /usr/bin/git exited with
│ 1: error: pathspec 'karpenter' did not match any file(s) known to git
│ 
╵

TeamRole:~/environment/eks-blueprint $ 





# PENDENTE
- Configurações adicionais usando o Fork do Allamand, não funciona.











# Switch our skiapp to uses Spot instances

Now in order to reduce even more our costs, let's enable Spot instances for our skiapp application.

    Edit the karpenter.yaml file in your workload repository, and edit the capacity-type line:

    - key: karpenter.sh/capacity-type
      operator: In
      values: ['on-demand', 'spot']

    Add the file and commit the change Watch Karpenter consolidation We can see Karpenter creating a new Spot instances and Cordoned an on-demand one to be replaced

After some times, Karpenter has replace our 3 on-demand instances with Spot instances.

    Our cluster costs has dropped from 755,55$/month to 608,82$/month when right sizing our skiapp Pod Spec
    The cluster cost then dropped to 498$/month when relying on spot instances for our ski app.

Important
For this exercice, We still had created a Managed Node Group of 3 instances of type m5.xlarge, which we see are really underutilized. So we can improve further our cluster costs by either changing the size of thoses nodes, or moving the pods on it to Fargate


- DE:

    - key: karpenter.sh/capacity-type
      operator: In
      values: ['on-demand']


- PARA:

    - key: karpenter.sh/capacity-type
      operator: In
      values: ['on-demand', 'spot']





fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git status
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        modified:   teams/team-riker/dev/templates/karpenter.yaml

no changes added to commit (use "git add" and/or "git commit -a")
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git add teams/team-riker/dev/templates/karpenter.yaml
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git commit -m "ajustado capacity type do Karpenter"
[main 718ad52] ajustado capacity type do Karpenter
 1 file changed, 1 insertion(+), 1 deletion(-)
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$ git push
Enumerating objects: 13, done.
Counting objects: 100% (13/13), done.
Delta compression using up to 8 threads
Compressing objects: 100% (7/7), done.
Writing objects: 100% (7/7), 652 bytes | 652.00 KiB/s, done.
Total 7 (delta 4), reused 0 (delta 0)
remote: Resolving deltas: 100% (4/4), completed with 4 local objects.
To github.com:fernandomullerjr/eks-blueprints-workloads.git
   967bc3a..718ad52  main -> main
fernando@debian10x64:~/cursos/kubernetes/aws-workshop-eks-blueprints/eks-blueprints-workloads$




- ANTES

7 nodes (10765m/22450m) 48.0% cpu ███████████████████░░░░░░░░░░░░░░░░░░░░░ $1.061/hour | $774.676/month 
101 pods (0 pending 101 running 101 bound)
ip-10-0-12-133.ec2.internal cpu ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  12% (18 pods) m5.xlarge/$0.192  On-De
ip-10-0-11-201.ec2.internal cpu ███████████░░░░░░░░░░░░░░░░░░░░░░░░  32% (18 pods) m5.xlarge/$0.192  On-De
ip-10-0-10-26.ec2.internal  cpu █████████████░░░░░░░░░░░░░░░░░░░░░░  38% (17 pods) m5.xlarge/$0.192  On-De
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034  Spot 
ip-10-0-10-218.ec2.internal cpu █████████████████████████████░░░░░░  84% (14 pods) t3a.xlarge/$0.150 On-De
ip-10-0-12-204.ec2.internal cpu ███████████████████████░░░░░░░░░░░░  66% (14 pods) t3a.xlarge/$0.150 On-De
ip-10-0-11-90.ec2.internal  cpu ██████████████████████████░░░░░░░░░  76% (13 pods) t3a.xlarge/$0.150 On-De
Press any key to quit




APP HEALTH
 Healthy
CURRENT SYNC STATUS
Synced
To main (718ad52)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
feature: adding skiapp which uses alb
LAST SYNC RESULT
Sync OK
To 718ad52
Succeeded 5 minutes ago (Thu Mar 02 2023 19:02:24 GMT-0300)
Author:
Fernando Muller Junior <fernandomj90@gmail.com> -
Comment:
ajustado capacity type do Karpenter



- Começou a agir, botando 1 on-demand em cordoned e subindo 1 Spot:

8 nodes (10970m/25370m) 43.2% cpu █████████████████░░░░░░░░░░░░░░░░░░░░░░░ $1.146/hour | $836.872/month 
106 pods (2 pending 104 running 106 bound)

ip-10-0-12-133.ec2.internal cpu ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  12% (18 pods) m5.xlarge/$0.192   On-Demand -        Ready         us-east-1c 
ip-10-0-11-201.ec2.internal cpu ███████████░░░░░░░░░░░░░░░░░░░░░░░░  32% (18 pods) m5.xlarge/$0.192   On-Demand -        Ready         us-east-1b 
ip-10-0-10-26.ec2.internal  cpu █████████████░░░░░░░░░░░░░░░░░░░░░░  38% (17 pods) m5.xlarge/$0.192   On-Demand -        Ready         us-east-1a 
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034   Spot      -        Ready burnham us-east-1a 
ip-10-0-10-218.ec2.internal cpu █████████████████████████████░░░░░░  84% (14 pods) t3a.xlarge/$0.150  On-Demand -        Ready default us-east-1a 
ip-10-0-12-204.ec2.internal cpu ███████████████████████░░░░░░░░░░░░  66% (14 pods) t3a.xlarge/$0.150  On-Demand -        Ready default us-east-1c 
ip-10-0-11-90.ec2.internal  cpu ██████████████████████████░░░░░░░░░  76% (13 pods) t3a.xlarge/$0.150  On-Demand Cordoned Ready default us-east-1b 
ip-10-0-11-122.ec2.internal cpu ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   7% (5 pods)  c6in.xlarge/$0.085 Spot      -        Ready default us-east-1b 
Press any key to quit



# PENDENTE
- Ver mais sobre o Kubecost



- Depois de algum tempo agindo, o Karpenter botou Spots adicionais e ficou balanceado, custo $$$ reduziu demais:

7 nodes (10765m/22450m) 48.0% cpu ███████████████████░░░░░░░░░░░░░░░░░░░░░ $0.851/hour | $620.938/month 
101 pods (0 pending 101 running 101 bound)

ip-10-0-12-133.ec2.internal cpu ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  17% (21 pods) m5.xlarge/$0.192   On-Demand - Ready         us-east-1c 
ip-10-0-11-201.ec2.internal cpu ███████████░░░░░░░░░░░░░░░░░░░░░░░░  32% (18 pods) m5.xlarge/$0.192   On-Demand - Ready         us-east-1b 
ip-10-0-10-26.ec2.internal  cpu █████████████░░░░░░░░░░░░░░░░░░░░░░  38% (17 pods) m5.xlarge/$0.192   On-Demand - Ready         us-east-1a 
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034   Spot      - Ready burnham us-east-1a 
ip-10-0-11-122.ec2.internal cpu ██████████████████████████░░░░░░░░░  76% (13 pods) c6in.xlarge/$0.085 Spot      - Ready default us-east-1b 
ip-10-0-10-180.ec2.internal cpu ██████████████████████████░░░░░░░░░  76% (13 pods) m3.xlarge/$0.069   Spot      - Ready default us-east-1a 
ip-10-0-12-65.ec2.internal  cpu ███████████████████████░░░░░░░░░░░░  67% (12 pods) c4.xlarge/$0.086   Spot      - Ready default us-east-1c 
Press



7 nodes (10765m/22450m) 48.0% cpu ███████████████████░░░░░░░░░░░░░░░░░░░░░ $0.851/hour | $620.938/month 
101 pods (0 pending 101 running 101 bound)

ip-10-0-12-133.ec2.internal cpu ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  17% (21 pods) m5.xlarge/$0.192   On-Demand - Ready         us-east-1c 
ip-10-0-11-201.ec2.internal cpu ███████████░░░░░░░░░░░░░░░░░░░░░░░░  32% (18 pods) m5.xlarge/$0.192   On-Demand - Ready         us-east-1b 
ip-10-0-10-26.ec2.internal  cpu █████████████░░░░░░░░░░░░░░░░░░░░░░  38% (17 pods) m5.xlarge/$0.192   On-Demand - Ready         us-east-1a 
ip-10-0-10-97.ec2.internal  cpu █████████████████░░░░░░░░░░░░░░░░░░  49% (7 pods)  c6a.large/$0.034   Spot      - Ready burnham us-east-1a 
ip-10-0-11-122.ec2.internal cpu ██████████████████████████░░░░░░░░░  76% (13 pods) c6in.xlarge/$0.085 Spot      - Ready default us-east-1b 
ip-10-0-10-180.ec2.internal cpu ██████████████████████████░░░░░░░░░  76% (13 pods) m3.xlarge/$0.069   Spot      - Ready default us-east-1a 
ip-10-0-12-65.ec2.internal  cpu ███████████████████████░░░░░░░░░░░░  67% (12 pods) c4.xlarge/$0.086   Spot      - Ready default us-east-1c 
Press any 





# Spot interruptions in action

As you may know, Spot instances are spare capacity and may be taken back by AWS at any time with a 2-minutes window. For stateless container workloads, this is not a big deal as Kubernetes can always rescheduled Pods to other available instances and Karpenter has integration to detect Spot termination signals through an SQS queue and will then drain the impacted instances

With AWS we can simulate Spot Interruptios using AWS FIS

    Go to the AWS console and select EC2, then click on Instances/Spot Requests
    Select an Spot request which correspond to our EKS cluster and click on Actions / Initiate Interruption
    This brings you to the AWS FIS console.

    keep Default role and click on Initiate interruption

In reaction to the interruption, we should see Karpenter to drain pods on the targeted instance, and then launch a new one to fullfill our pending pods.

You can check Karpenter logs that has detect the Interruption

kubectl logs -n karpenter deployment/karpenter -f



Conclusion

As a Team Riker member, you have successfully leverage Karpenter's ability to schedule your workloads from your ArgoCD git repository, and dynamically adapt the cluster size depending on application needs.

You already managed to rely on Kubecost to better adapt your resources workloads requirements to even more reduce your cluster's costs.

We finally see how Spot instances could improve your cost saving, and how Karpenter and AWS managed Spot interruptions so that your workloads won't be impaired.





git@github.com:fernandomullerjr/aws-workshop-eks-blueprints.git

#### Ajustando repositorio
git init
git remote add origin git@github.com:fernandomullerjr/aws-workshop-eks-blueprints.git
git branch -M main
git push -uf origin main
git pull origin main
git push --set-upstream origin main



git status
git add .
git commit -m "WORKSHOP AWS - EKS Blueprints."
eval $(ssh-agent -s)
ssh-add /home/fernando/.ssh/chave-debian10-github
git push
git status






remote: Resolving deltas: 100% (5/5), completed with 2 local objects.
remote: error: Trace: baa1951463cefd0ec4faedbbf336272b67b70c49cb54d03f8c0045d42016ec03
remote: error: See http://git.io/iEPt8g for more information.
remote: error: File material-original/eks-blueprint.zip is 177.32 MB; this exceeds GitHub's file size limit of 100.00 MB
remote: error: GH001: Large files detected. You may want to try Git Large File Storage - https://git-lfs.github.com.
To github.com:fernandomullerjr/aws-workshop-eks-blueprints.git
 ! [remote rejected] main -> main (pre-receive hook declined)
error: failed to push some refs to 'git@github.com:fernandomullerjr/aws-workshop-eks-blueprints.git'




git add -u
git reset -- material-original/eks-blueprint.zip
git reset -- 01-eks-cluster-terraform-simples/.terraform/*





git filter-branch -f --index-filter 'git rm --cached --ignore-unmatch material-original/eks-blueprint.zip'
