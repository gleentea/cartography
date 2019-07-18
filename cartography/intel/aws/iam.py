import logging
import botocore.exceptions
import policyuniverse.statement

from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)


def get_group_policies(session, group_name):
    client = session.client('iam')
    paginator = client.get_paginator('list_group_policies')
    policy_names = []
    try:
        for page in paginator.paginate(GroupName=group_name):
            policy_names.extend(page['PolicyNames'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' group policies. (%s)", group_name, e)
        else:
            raise

    paginator = client.get_paginator('list_attached_group_policies')
    attached_policies = []
    try:
        for page in paginator.paginate(GroupName=group_name):
            attached_policies.extend(page['AttachedPolicies'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' attached group policies. (%s)", group_name, e)
        else:
            raise

    return {'PolicyNames': policy_names, 'AttachedPolicies': attached_policies}


def get_group_policy_info(session, group_name, policy_name):
    client = session.client('iam')
    try:
        return client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' policy info of '%s'. (%s)", policy_name, group_name, e)
        else:
            raise

    return {}


def get_group_membership_data(session, group_name):
    client = session.client('iam')
    try:
        return client.get_group(GroupName=group_name)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get group membership of '%s'. (%s)", group_name, e)
        else:
            raise

    return {}


def get_user_list_data(session):
    client = session.client('iam')
    paginator = client.get_paginator('list_users')
    users = []
    try:
        for page in paginator.paginate():
            users.extend(page['Users'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get user list. (%s)", e)
        else:
            raise
    return {'Users': users}


def get_user_policies(session, user_name):
    client = session.client('iam')
    paginator = client.get_paginator('list_user_policies')
    policy_names = []
    try:
        for page in paginator.paginate(UserName=user_name):
            policy_names.extend(page['PolicyNames'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' user policies. (%s)", user_name, e)
        else:
            raise

    paginator = client.get_paginator('list_attached_user_policies')
    attached_policies = []
    try:
        for page in paginator.paginate(UserName=user_name):
            attached_policies.extend(page['AttachedPolicies'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' attached user policies. (%s)", user_name, e)
        else:
            raise

    return {'PolicyNames': policy_names, 'AttachedPolicies': attached_policies}


def get_user_policy_info(session, user_name, policy_name):
    client = session.client('iam')
    try:
        return client.get_user_policy(UserName=user_name, PolicyName=policy_name)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' user policy info. (%s)", policy_name, e)
        else:
            raise
    return {}


def get_group_list_data(session):
    client = session.client('iam')
    paginator = client.get_paginator('list_groups')
    groups = []
    try:
        for page in paginator.paginate():
            groups.extend(page['Groups'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get group list. (%s)", e)
        else:
            raise
    return {'Groups': groups}


def get_policy_list_data(session, saved_policy):
    client = session.client('iam')
    paginator = client.get_paginator('list_policies')
    policies = []
    try:
        for page in paginator.paginate(OnlyAttached=True):
            for policy in page['Policies']:
                if policy['AttachmentCount'] < 1:
                    continue
                policies.append(policy)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get policy list. (%s)", e)
        else:
            raise

    for i,policy in enumerate(policies):
        try:
            if saved_policy.get(policy['Arn'],{}).get('defaultversionid',"") == policy['DefaultVersionId']:
                policy = saved_policy[policy['Arn']]
                logger.debug("A policy named '%s' is not changed, skip", policy['arn'])
                key=['Arn','PolicyId','Path','DefaultVersionId','CreateDate','UpdateDate','IsAttachable','AttachemtnCount']
                for k in key:
                    policies[i][k] = policy[k.lower()]
                policies[i]['PolicyName'] = policy['name']
            else:
                document = client.get_policy_version(PolicyArn=policy['Arn'],VersionId=policy['DefaultVersionId'])
                policies[i]['Statement'] = document['PolicyVersion']['Document']['Statement']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.warn("Cannot get policy list. (%s)", e)
            else:
                raise
    return {'Policies': policies}


def get_role_list_data(session):
    client = session.client('iam')
    paginator = client.get_paginator('list_roles')
    roles = []
    try:
        for page in paginator.paginate():
            roles.extend(page['Roles'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get role list. (%s)", e)
        else:
            raise
    return {'Roles': roles}


def get_role_policies(session, role_name):
    client = session.client('iam')
    paginator = client.get_paginator('list_role_policies')
    policy_names = []
    try:
        for page in paginator.paginate(RoleName=role_name):
            policy_names.extend(page['PolicyNames'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' role policies. (%s)", role_name, e)
        else:
            raise

    paginator = client.get_paginator('list_attached_role_policies')
    attached_policies = []
    try:
        for page in paginator.paginate(RoleName=role_name):
            attached_policies.extend(page['AttachedPolicies'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' attached role policies. (%s)", role_name, e)
        else:
            raise

    return {'PolicyNames': policy_names, 'AttachedPolicies': attached_policies}


def get_role_policy_info(session, role_name, policy_name):
    client = session.client('iam')
    try:
        return client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' role policy info. (%s)", policy_name, e)
        else:
            raise
    return {}


def get_account_access_key_data(session, username):
    client = session.client('iam')
    # NOTE we can get away without using a paginator here because users are limited to two access keys
    try:
        return client.list_access_keys(UserName=username)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get '%s' account access key. (%s)", username, e)
        else:
            raise
    return {}


def get_instance_profile_list_data(session):
    client = session.client('iam')
    paginator = client.get_paginator('list_instance_profiles')
    profiles = []
    try:
        for page in paginator.paginate():
            profiles.extend(page['InstanceProfiles'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logger.warn("Cannot get instance profile list. (%s)", e)
        else:
            raise
    return profiles


def load_users(session, users, current_aws_account_id, aws_update_tag):
    ingest_user = """
    MERGE (unode:AWSUser{arn: {ARN}})
    ON CREATE SET unode:AWSPrincipal, unode.userid = {USERID}, unode.firstseen = timestamp(),
    unode.createdate = {CREATE_DATE}
    SET unode.name = {USERNAME}, unode.path = {PATH}, unode.passwordlastused = {PASSWORD_LASTUSED},
    unode.lastupdated = {aws_update_tag}
    WITH unode
    MATCH (aa:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (aa)-[r:RESOURCE]->(unode)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for user in users:
        session.run(
            ingest_user,
            ARN=user["Arn"],
            USERID=user["UserId"],
            CREATE_DATE=str(user["CreateDate"]),
            USERNAME=user["UserName"],
            PATH=user["Path"],
            PASSWORD_LASTUSED=str(user.get("PasswordLastUsed", "")),
            AWS_ACCOUNT_ID=current_aws_account_id,
            aws_update_tag=aws_update_tag
        ).detach()


def load_groups(session, groups, current_aws_account_id, aws_update_tag):
    ingest_group = """
    MERGE (gnode:AWSGroup{arn: {ARN}})
    ON CREATE SET gnode.groupid = {GROUP_ID}, gnode.firstseen = timestamp(), gnode.createdate = {CREATE_DATE}
    SET gnode.name = {GROUP_NAME}, gnode.path = {PATH},gnode.lastupdated = {aws_update_tag}
    WITH gnode
    MATCH (aa:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (aa)-[r:RESOURCE]->(gnode)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for group in groups:
        session.run(
            ingest_group,
            ARN=group["Arn"],
            GROUP_ID=group["GroupId"],
            CREATE_DATE=str(group["CreateDate"]),
            GROUP_NAME=group["GroupName"],
            PATH=group["Path"],
            AWS_ACCOUNT_ID=current_aws_account_id,
            aws_update_tag=aws_update_tag
        ).detach()


def _load_policy_actions(session, policy_arn, statement, aws_update_tag):
    ingest_policy_action= """
    MATCH (pnode:AWSPolicy{arn: {ARN}})
    SET pnode.lastupdated = {aws_update_tag}
    WITH pnode
    MERGE (action:AWSIAMAction{name: {IAMAction}})
    ON CREATE SET action.firstseen=timestamp()
    SET action.lastupdated={aws_update_tag}
    WITH pnode,action
    MERGE (action)<-[r:AWS_IAM_ACTION_%s]-(pnode)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    if type(statement) != type(list()):
        statement = [statement]
    for st in statement:
        parsed_statement = policyuniverse.statement.Statement(st)
        query = ingest_policy_action % parsed_statement.effect.upper()
        for action in parsed_statement.actions_expanded:
            session.run(
                query,
                ARN=policy_arn,
                IAMAction=action,
                aws_update_tag=aws_update_tag
            ).detach()


def load_policies(session, policies, current_aws_account_id, aws_update_tag):
    ingest_policy = """
    MERGE (pnode:AWSPolicy{arn: {ARN}})
    ON CREATE SET pnode.policyid = {POLICY_ID}, pnode.firstseen = timestamp(), pnode.createdate = {CREATE_DATE}
    SET pnode.name = {POLICY_NAME}, pnode.path = {PATH}, pnode.defaultversionid = {DEFAULT_VERSION_ID},
    pnode.updatedate = {POLICY_UPDATE}, pnode.isattachable = {IS_ATTACHABLE},
    pnode.attachmentcount = {ATTACHMENT_COUNT},
    pnode.lastupdated = {aws_update_tag}
    WITH pnode
    MATCH (aa:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (aa)-[r:AWS_POLICY]->(pnode)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for policy in policies:
        session.run(
            ingest_policy,
            ARN=policy["Arn"],
            POLICY_ID=policy["PolicyId"],
            POLICY_NAME=policy["PolicyName"],
            PATH=policy["Path"],
            DEFAULT_VERSION_ID=policy["DefaultVersionId"],
            CREATE_DATE=str(policy["CreateDate"]),
            POLICY_UPDATE=str(policy["UpdateDate"]),
            IS_ATTACHABLE=policy["IsAttachable"],
            ATTACHMENT_COUNT=policy["AttachmentCount"],
            AWS_ACCOUNT_ID=current_aws_account_id,
            aws_update_tag=aws_update_tag
        ).detach()
        logger.debug("syncing %s actions...", policy["PolicyName"])
        _load_policy_actions(session, policy["Arn"], policy.get("Statement",[]), aws_update_tag)


def load_roles(session, roles, current_aws_account_id, aws_update_tag):
    ingest_role = """
    MERGE (rnode:AWSRole{arn: {Arn}})
    ON CREATE SET rnode:AWSPrincipal, rnode.roleid = {RoleId}, rnode.firstseen = timestamp(),
    rnode.createdate = {CreateDate}
    SET rnode.name = {RoleName}, rnode.path = {Path}
    SET rnode.lastupdated = {aws_update_tag}
    WITH rnode
    MATCH (aa:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (aa)-[r:AWS_ROLE]->(rnode)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    ingest_policy_statement = """
    MERGE (spnnode:AWSPrincipal{arn: {SpnArn}})
    ON CREATE SET spnnode.firstseen = timestamp()
    SET spnnode.lastupdated = {aws_update_tag}, spnnode.type = {SpnType}
    WITH spnnode
    MATCH (role:AWSRole{arn: {RoleArn}})
    MERGE (role)-[r:TRUSTS_AWS_PRINCIPAL]->(spnnode)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    # TODO support conditions

    for role in roles:
        session.run(
            ingest_role,
            Arn=role["Arn"],
            RoleId=role["RoleId"],
            CreateDate=str(role["CreateDate"]),
            RoleName=role["RoleName"],
            Path=role["Path"],
            AWS_ACCOUNT_ID=current_aws_account_id,
            aws_update_tag=aws_update_tag
        ).detach()

        for statement in role["AssumeRolePolicyDocument"]["Statement"]:
            principal = statement["Principal"]
            principal_values = []
            if 'AWS' in principal:
                principal_type, principal_values = 'AWS', principal['AWS']
            elif 'Service' in principal:
                principal_type, principal_values = 'Service', principal['Service']
            if not isinstance(principal_values, list):
                principal_values = [principal_values]
            for principal_value in principal_values:
                session.run(
                    ingest_policy_statement,
                    SpnArn=principal_value,
                    SpnType=principal_type,
                    RoleArn=role['Arn'],
                    aws_update_tag=aws_update_tag
                ).detach()


def load_group_memberships(session, group_memberships, aws_update_tag):
    ingest_membership = """
    MATCH (group:AWSGroup{name: {GroupName}})
    WITH group
    MATCH (user:AWSUser{arn: {PrincipalArn}})
    MERGE (user)-[r:MEMBER_AWS_GROUP]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for group_name, membership_data in group_memberships.items():
        for info in membership_data["Users"]:
            principal_arn = info["Arn"]
            session.run(
                ingest_membership,
                GroupName=group_name,
                PrincipalArn=principal_arn,
                aws_update_tag=aws_update_tag
            ).detach()


def _find_roles_assumable_in_policy(policy_data):
    ret = []
    statements = policy_data["PolicyDocument"]["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        parsed_statement = policyuniverse.statement.Statement(statement)
        if parsed_statement.effect == 'Allow' and 'sts:assumerole' in parsed_statement.actions_expanded:
            ret.extend(list(parsed_statement.resources))
    return ret


def _load_inline_policy(session, entity_arn, policy_data, aws_update_tag):
    ingest_inline_policy = """
    MERGE (policy:AWSPolicy{arn: {ARN}})
    ON CREATE SET policy.firstseen = timestamp()
    SET policy.name = {PolicyName}
    SET policy.lastupdated = {aws_update_tag}
    """
    session.run(
        ingest_inline_policy,
        ARN=entity_arn,
        PolicyName=policy_data['PolicyName'],
        aws_update_tag=aws_update_tag
    ).detach()
    statement = [statement for statement in policy_data.get("PolicyDocument",{}).get("Statement",[])]
    _load_policy_actions(session, entity_arn, statement, aws_update_tag)


def load_user_policies(session, users_policies, aws_update_tag):
    ingest_policies_assume_role = """
    MATCH (user:AWSUser{arn: {UserArn}})
    WITH user
    MERGE (role:AWSRole{arn: {RoleArn}})
    ON CREATE SET role.firstseen = timestamp()
    SET role.lastupdated = {aws_update_tag}
    WITH role, user
    MERGE (user)-[r:STS_ASSUMEROLE_ALLOW]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for user_arn, policies in users_policies.items():
        for policy_name, policy_data in policies.items():
            for role_arn in _find_roles_assumable_in_policy(policy_data):
                # TODO resource ARNs may contain wildcards, e.g. arn:aws:iam::*:role/admin --
                # TODO policyuniverse can't expand resource wildcards so further thought is needed here
                session.run(
                    ingest_policies_assume_role,
                    UserArn=user_arn,
                    RoleArn=role_arn,
                    aws_update_tag=aws_update_tag
                ).detach()


def load_user_inline_policies(session, aws_account_id, user_policies, aws_update_tag):
    ingest_user_inline_policy = """
    MATCH (user:AWSUser{arn:{UserArn}})
    WITH user
    MATCH (policy:AWSPolicy{arn:{PolicyArn}})
    WITH user,policy
    MERGE (policy)-[r:AWS_INLINE_POLICY]->(user)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """
    for user_arn, policies in user_policies.items():
        for policy_name, policy_data in policies.items():
            arn = "{}:inlinepolicy:{}:{}".format(aws_account_id, user_arn.split('/')[-1], policy_name)
            _load_inline_policy(session, arn, policy_data, aws_update_tag)
            session.run(
                ingest_user_inline_policy,
                UserArn=user_arn,
                PolicyArn=arn,
                aws_update_tag=aws_update_tag
            ).detach()


def load_attached_user_policies(session, attached_user_policies, aws_update_tag):
    ingest_attached_user_policies = """
    MATCH (policy:AWSPolicy{arn: {PolicyArn}})
    WITH policy
    MERGE (user:AWSUser{arn: {UserArn}})
    ON CREATE SET user.firstseen = timestamp()
    SET user.lastupdated = {aws_update_tag}
    WITH user, policy
    MERGE (policy)-[r:AWS_ATTACHED_POLICY]->(user)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for user_arn, policies in attached_user_policies.items():
        for policy_arn in policies:
            session.run(
                ingest_attached_user_policies,
                UserArn=user_arn,
                PolicyArn=policy_arn,
                aws_update_tag=aws_update_tag
            ).detach()


def load_group_policies(session, group_policies, aws_update_tag):
    ingest_policies_assume_role = """
    MATCH (group:AWSGroup{arn: {GroupArn}})
    WITH group
    MERGE (role:AWSRole{arn: {RoleArn}})
    ON CREATE SET role.firstseen = timestamp()
    SET role.lastupdated = {aws_update_tag}
    WITH role, group
    MERGE (group)-[r:STS_ASSUMEROLE_ALLOW]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for group_arn, policies in group_policies.items():
        for policy_name, policy_data in policies.items():
            for role_arn in _find_roles_assumable_in_policy(policy_data):
                # TODO resource ARNs may contain wildcards, e.g. arn:aws:iam::*:role/admin --
                # TODO policyuniverse can't expand resource wildcards so further thought is needed here
                session.run(
                    ingest_policies_assume_role,
                    GroupArn=group_arn,
                    RoleArn=role_arn,
                    aws_update_tag=aws_update_tag
                ).detach()


def load_group_inline_policies(session, aws_account_id, group_policies, aws_update_tag):
    ingest_group_inline_policy = """
    MATCH (group:AWSGroup{arn:{GroupArn}})
    WITH group
    MATCH (policy:AWSPolicy{arn:{PolicyArn}})
    WITH group,policy
    MERGE (policy)-[r:AWS_INLINE_POLICY]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """
    for group_arn, policies in group_policies.items():
        for policy_name, policy_data in policies.items():
            arn = "{}:inlinepolicy:{}:{}".format(aws_account_id, group_arn.split('/')[-1], policy_name)
            _load_inline_policy(session, arn, policy_data, aws_update_tag)
            session.run(
                ingest_group_inline_policy,
                GroupArn=group_arn,
                PolicyArn=arn,
                aws_update_tag=aws_update_tag
            ).detach()


def load_attached_group_policies(session, attached_group_policies, aws_update_tag):
    ingest_attached_group_policies = """
    MATCH (policy:AWSPolicy{arn: {PolicyArn}})
    WITH policy
    MERGE (group:AWSGroup{arn: {GroupArn}})
    ON CREATE SET group.firstseen = timestamp()
    SET group.lastupdated = {aws_update_tag}
    WITH group, policy
    MERGE (policy)-[r:AWS_ATTACHED_POLICY]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for group_arn, policies in attached_group_policies.items():
        for policy_arn in policies:
            session.run(
                ingest_attached_group_policies,
                GroupArn=group_arn,
                PolicyArn=policy_arn,
                aws_update_tag=aws_update_tag
            ).detach()


def load_role_policies(session, role_policies, aws_update_tag):
    ingest_policies_assume_role = """
    MATCH (assumer:AWSRole{arn: {AssumerRoleArn}})
    WITH assumer
    MERGE (role:AWSRole{arn: {RoleArn}})
    ON CREATE SET role.firstseen = timestamp()
    SET role.lastupdated = {aws_update_tag}
    WITH role, assumer
    MERGE (assumer)-[r:STS_ASSUMEROLE_ALLOW]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for assumer_role_arn, policies in role_policies.items():
        for policy_name, policy_data in policies.items():
            for role_arn in _find_roles_assumable_in_policy(policy_data):
                # TODO resource ARNs may contain wildcards, e.g. arn:aws:iam::*:role/admin --
                # TODO policyuniverse can't expand resource wildcards so further thought is needed here
                session.run(
                    ingest_policies_assume_role,
                    AssumerRoleArn=assumer_role_arn,
                    RoleArn=role_arn,
                    aws_update_tag=aws_update_tag
                ).detach()


def load_role_inline_policies(session, aws_account_id, role_policies, aws_update_tag):
    ingest_role_inline_policy = """
    MATCH (role:AWSRole{arn:{RoleArn}})
    WITH role
    MATCH (policy:AWSPolicy{arn:{PolicyArn}})
    WITH role,policy
    MERGE (policy)-[r:AWS_INLINE_POLICY]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """
    for role_arn, policies in role_policies.items():
        for policy_name, policy_data in policies.items():
            arn = "{}:inlinepolicy:{}:{}".format(aws_account_id, role_arn.split('/')[-1], policy_name)
            _load_inline_policy(session, arn, policy_data, aws_update_tag)
            session.run(
                ingest_role_inline_policy,
                RoleArn=role_arn,
                PolicyArn=arn,
                aws_update_tag=aws_update_tag
            ).detach()


def load_attached_role_policies(session, attached_role_policies, aws_update_tag):
    ingest_attached_role_policies = """
    MATCH (policy:AWSPolicy{arn: {PolicyArn}})
    WITH policy
    MERGE (role:AWSRole{arn: {RoleArn}})
    ON CREATE SET role.firstseen = timestamp()
    SET role.lastupdated = {aws_update_tag}
    WITH role, policy
    MERGE (policy)-[r:AWS_ATTACHED_POLICY]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for role_arn, policies in attached_role_policies.items():
        for policy_arn in policies:
            session.run(
                ingest_attached_role_policies,
                RoleArn=role_arn,
                PolicyArn=policy_arn,
                aws_update_tag=aws_update_tag
            ).detach()


def load_user_access_keys(session, user_access_keys, aws_update_tag):
    # TODO change the node label to reflect that this is a user access key, not an account access key
    ingest_account_key = """
    MATCH (user:AWSUser{name: {UserName}})
    WITH user
    MERGE (key:AccountAccessKey{accesskeyid: {AccessKeyId}})
    ON CREATE SET key.firstseen = timestamp(), key.createdate = {CreateDate}
    SET key.status = {Status}, key.lastupdated = {aws_update_tag}
    WITH user,key
    MERGE (user)-[r:AWS_ACCESS_KEY]->(key)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for username, access_keys in user_access_keys.items():
        for key in access_keys["AccessKeyMetadata"]:
            if key.get('AccessKeyId'):
                session.run(
                    ingest_account_key,
                    UserName=username,
                    AccessKeyId=key['AccessKeyId'],
                    CreateDate=str(key['CreateDate']),
                    Status=key['Status'],
                    aws_update_tag=aws_update_tag
                ).detach()

def load_instance_profiles(session, instance_profiles,aws_update_tag):
    ingest_instance_profile = """
    MATCH (role:AWSRole{arn: {ROLE_ARN}})
    WITH role
    MERGE (profile:AWSInstanceProfile{arn: {ARN}})
    ON CREATE SET profile.firstseen = timestamp()
    SET profile.name = {NAME}
    SET profile.path = {PATH}
    SET profile.instanceprofileid = {ID}
    SET profile.createdate = {CREATE_DATE}
    SET profile.lastupdated = {aws_update_tag}
    WITH role, profile
    MERGE (role)-[r:AWS_ATTACHED_ROLE]->(profile)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for profile in instance_profiles:
        if len(profile['Roles']) < 1:
            continue
        session.run(
            ingest_instance_profile,
            ROLE_ARN=profile['Roles'][0]['Arn'],
            ARN=profile['Arn'],
            NAME=profile['InstanceProfileName'],
            PATH=profile['Path'],
            ID=profile['InstanceProfileId'],
            CREATE_DATE=profile['CreateDate'],
            aws_update_tag=aws_update_tag
        ).detach()


def sync_users(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM users for account '%s'.", current_aws_account_id)
    data = get_user_list_data(boto3_session)
    load_users(neo4j_session, data['Users'], current_aws_account_id, aws_update_tag)
    run_cleanup_job('aws_import_users_cleanup.json', neo4j_session, common_job_parameters)


def sync_groups(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM groups for account '%s'.", current_aws_account_id)
    data = get_group_list_data(boto3_session)
    load_groups(neo4j_session, data['Groups'], current_aws_account_id, aws_update_tag)
    run_cleanup_job('aws_import_groups_cleanup.json', neo4j_session, common_job_parameters)


def sync_policies(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM policies for account '%s'.", current_aws_account_id)
    query = "MATCH (policy:AWSPolicy) RETURN *;"
    result = neo4j_session.run(query)
    saved_policy = {}
    for d in result:
        saved_policy[d.get('policy').get('arn')] = d.get('policy')
    data = get_policy_list_data(boto3_session, saved_policy)
    load_policies(neo4j_session, data['Policies'], current_aws_account_id, aws_update_tag)
    run_cleanup_job('aws_import_policies_cleanup.json', neo4j_session, common_job_parameters)


def sync_roles(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM roles for account '%s'.", current_aws_account_id)
    data = get_role_list_data(boto3_session)
    load_roles(neo4j_session, data['Roles'], current_aws_account_id, aws_update_tag)
    run_cleanup_job('aws_import_roles_cleanup.json', neo4j_session, common_job_parameters)


def sync_user_policies(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM user policies for account '%s'.", current_aws_account_id)
    query = "MATCH (user:AWSUser)<-[:RESOURCE]-(AWSAccount{id: {AWS_ACCOUNT_ID}}) return user.name as name, user.arn as arn;"
    result = neo4j_session.run(query, AWS_ACCOUNT_ID=current_aws_account_id)
    users = {}
    for record in result:
        users[record['arn']] = record['name']
    users_policies = {}
    attached_users_policies = {}
    for user_arn, user_name in users.items():
        logger.debug("Syncing '%s' user policy...", user_name)
        users_policies[user_arn] = {}
        user_policies = get_user_policies(boto3_session, user_name)
        for policy_name in user_policies['PolicyNames']:
            users_policies[user_arn][policy_name] = get_user_policy_info(boto3_session, user_name, policy_name)
        attached_users_policies[user_arn] = list(set([p['PolicyArn'] for p in user_policies['AttachedPolicies']]))
    load_user_policies(neo4j_session, users_policies, aws_update_tag)
    load_user_inline_policies(neo4j_session, current_aws_account_id, users_policies, aws_update_tag)
    load_attached_user_policies(neo4j_session, attached_users_policies, aws_update_tag)
    run_cleanup_job(
        'aws_import_users_policy_cleanup.json',
        neo4j_session,
        common_job_parameters
    )


def sync_group_memberships(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM group membership for account '%s'.", current_aws_account_id)
    query = "MATCH (group:AWSGroup)<-[:RESOURCE]-(AWSAccount{id: {AWS_ACCOUNT_ID}}) return group.name as name;"
    result = neo4j_session.run(query, AWS_ACCOUNT_ID=current_aws_account_id)
    groups = [r['name'] for r in result]
    groups_membership = {name: get_group_membership_data(boto3_session, name) for name in groups}
    load_group_memberships(neo4j_session, groups_membership, aws_update_tag)
    run_cleanup_job(
        'aws_import_groups_membership_cleanup.json',
        neo4j_session,
        common_job_parameters
    )


def sync_group_policies(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM group policies for account '%s'.", current_aws_account_id)
    query = "MATCH (group:AWSGroup)<-[:RESOURCE]-(AWSAccount{id: {AWS_ACCOUNT_ID}}) return group.name as name, group.arn as arn;"
    result = neo4j_session.run(query, AWS_ACCOUNT_ID=current_aws_account_id)
    groups = {}
    for record in result:
        groups[record['arn']] = record['name']
    groups_policies = {}
    attached_groups_policies = {}
    for group_arn, group_name in groups.items():
        logger.debug("Syncing '%s' group policy...", group_name)
        groups_policies[group_arn] = {}
        group_policies = get_group_policies(boto3_session, group_name)
        for policy_name in group_policies['PolicyNames']:
            groups_policies[group_arn][policy_name] = get_group_policy_info(boto3_session, group_name, policy_name)
        attached_groups_policies[group_arn] = list(set([p['PolicyArn'] for p in group_policies['AttachedPolicies']]))
    load_group_policies(neo4j_session, groups_policies, aws_update_tag)
    load_group_inline_policies(neo4j_session, current_aws_account_id, groups_policies, aws_update_tag)
    load_attached_group_policies(neo4j_session, attached_groups_policies, aws_update_tag)
    run_cleanup_job(
        'aws_import_groups_policy_cleanup.json',
        neo4j_session,
        common_job_parameters
    )


def sync_role_policies(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM role policies for account '%s'.", current_aws_account_id)
    query = """
    MATCH (role:AWSRole)<-[:AWS_ROLE]-(AWSAccount{id: {AWS_ACCOUNT_ID}})
    WHERE exists(role.name)
    RETURN role.name AS name, role.arn as arn;
    """
    result = neo4j_session.run(query, AWS_ACCOUNT_ID=current_aws_account_id)
    roles = {}
    for record in result:
        roles[record['arn']] = record['name']
    roles_policies = {}
    attached_roles_policies = {}
    for role_arn, role_name in roles.items():
        logger.debug("Syncing '%s' role policy...", role_name)
        roles_policies[role_arn] = {}
        role_policies = get_role_policies(boto3_session, role_name)
        for policy_name in role_policies['PolicyNames']:
            roles_policies[role_arn][policy_name] = get_role_policy_info(boto3_session, role_name, policy_name)
        attached_roles_policies[role_arn] = list(set([p['PolicyArn'] for p in role_policies['AttachedPolicies']]))
    load_role_policies(neo4j_session, roles_policies, aws_update_tag)
    load_role_inline_policies(neo4j_session, current_aws_account_id, roles_policies, aws_update_tag)
    load_attached_role_policies(neo4j_session, attached_roles_policies, aws_update_tag)
    run_cleanup_job(
        'aws_import_roles_policy_cleanup.json',
        neo4j_session,
        common_job_parameters
    )


def sync_user_access_keys(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM user access keys for account '%s'.", current_aws_account_id)
    query = "MATCH (user:AWSUser)<-[:RESOURCE]-(AWSAccount{id: {AWS_ACCOUNT_ID}}) return user.name as name"
    result = neo4j_session.run(query, AWS_ACCOUNT_ID=current_aws_account_id)
    usernames = [r['name'] for r in result]
    account_access_key = {name: get_account_access_key_data(boto3_session, name) for name in usernames}
    load_user_access_keys(neo4j_session, account_access_key, aws_update_tag)
    run_cleanup_job(
        'aws_import_account_access_key_cleanup.json',
        neo4j_session,
        common_job_parameters
    )


def sync_instance_profiles(neo4j_session, boto3_session, current_aws_account_id, aws_update_tag, common_job_parameters):
    logger.debug("Syncing IAM instance profiles for account '%s'.", current_aws_account_id)
    profiles = get_instance_profile_list_data(boto3_session)
    load_instance_profiles(neo4j_session, profiles, aws_update_tag)
    run_cleanup_job(
        'aws_import_instance_profile.json',
        neo4j_session,
        common_job_parameters
    )

def sync(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters):
    logger.info("Syncing IAM for account '%s'.", account_id)
    sync_users(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_groups(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_policies(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_roles(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_group_memberships(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_user_policies(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_group_policies(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_role_policies(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_user_access_keys(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    sync_instance_profiles(neo4j_session, boto3_session, account_id, update_tag, common_job_parameters)
    run_cleanup_job('aws_import_principals_cleanup.json', neo4j_session, common_job_parameters)
