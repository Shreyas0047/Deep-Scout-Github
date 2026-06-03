from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RemediationInfo:
    risk: str
    severity_reason: str
    immediate_steps: list[str] = field(default_factory=list)
    revoke_urls: list[str] = field(default_factory=list)
    git_cleanup_command: str = ""
    prevention_tips: list[str] = field(default_factory=list)
    reference_urls: list[str] = field(default_factory=list)


_REMEDIATION_MAP: dict[str, RemediationInfo] = {
    "AWS Access Key": RemediationInfo(
        risk="Attacker can use this key to access your AWS account, spin up EC2 instances, access S3 buckets, and incur massive bills via crypto mining. Average breach cost: $50,000+.",
        severity_reason="Direct cloud infrastructure access. Automated bots scan for exposed AWS keys within minutes of commit.",
        immediate_steps=[
            "1. Immediately revoke the exposed key via AWS IAM console",
            "2. Review CloudTrail logs for any unauthorized usage since the commit timestamp",
            "3. Rotate all services, applications, and users that relied on this key",
            "4. Remove the key from git history using BFG Repo-Cleaner",
            "5. If key was used by CI/CD, update secrets in your CI/CD provider",
        ],
        revoke_urls=[
            "https://console.aws.amazon.com/iam/home#/security_credentials",
            "https://console.aws.amazon.com/cloudtrail/home",
        ],
        git_cleanup_command="bfg --replace-text secrets.txt <repository>.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive",
        prevention_tips=[
            "Use AWS IAM roles instead of long-lived access keys",
            "Use AWS Secrets Manager or Parameter Store for credential storage",
            "Add AWS key detection to pre-commit hooks",
            "Never hardcode keys in source code — use environment variables",
        ],
        reference_urls=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
    ),
    "AWS Secret Key": RemediationInfo(
        risk="Together with an AWS Access Key, this provides full API access to your AWS account. Secret keys are meant to be kept confidential at all times.",
        severity_reason="Combined with the access key ID, this grants unrestricted AWS API access.",
        immediate_steps=[
            "1. Immediately revoke the compromised access key pair via AWS IAM console",
            "2. Generate a new access key and update all dependent services",
            "3. Audit CloudTrail for unauthorized API calls",
            "4. Remove secret from git history",
        ],
        revoke_urls=["https://console.aws.amazon.com/iam/home#/security_credentials"],
        git_cleanup_command="bfg --replace-text secrets.txt <repository>.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive",
        prevention_tips=[
            "Use temporary security credentials (STS) instead of long-lived keys",
            "Rotate keys regularly",
            "Store secrets in AWS Secrets Manager",
        ],
    ),
    "AWS Session Token": RemediationInfo(
        risk="Temporary AWS credential that could still be valid and provide unauthorized access to your AWS resources.",
        severity_reason="Even temporary tokens can provide significant access depending on the associated IAM role.",
        immediate_steps=[
            "1. Determine the IAM role associated with this session token",
            "2. If the token is still within its expiration window, immediately revoke the parent IAM role's credentials",
            "3. Audit CloudTrail for any activity using this token",
        ],
        revoke_urls=["https://console.aws.amazon.com/iam/home#/roles"],
        git_cleanup_command="bfg --replace-text secrets.txt <repository>.git",
        prevention_tips=[
            "Reduce session token duration",
            "Avoid hardcoding any temporary credentials in source code",
        ],
    ),
    "GitHub Token (Classic)": RemediationInfo(
        risk="Full access to all repositories the token has scope over. Attacker can clone private repos, push malicious code, create backdoors, and exfiltrate sensitive data.",
        severity_reason="Can compromise your entire GitHub organization. Tokens often have `repo` scope covering all repositories.",
        immediate_steps=[
            "1. Immediately revoke the token at GitHub Settings → Developer settings → Personal access tokens",
            "2. Check audit log for any unauthorized access using this token",
            "3. Rotate any webhooks or integrations that used this token",
            "4. Review if any repositories were cloned or modified by the exposed token",
        ],
        revoke_urls=["https://github.com/settings/tokens"],
        git_cleanup_command="N/A — revoke token directly. No git history cleanup needed.",
        prevention_tips=[
            "Use fine-grained tokens with minimal repository and permission scopes",
            "Set expiration dates on all tokens (90 days max recommended)",
            "Use GitHub Actions OIDC tokens instead of PATs for CI/CD",
            "Regularly audit and rotate tokens",
        ],
        reference_urls=["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"],
    ),
    "GitHub Token (Fine-grained)": RemediationInfo(
        risk="Fine-grained access to specific repositories. While scoped, attacker can still access, modify, or exfiltrate data from the permitted repositories.",
        severity_reason="Scoped access is better than classic tokens, but still dangerous if the permitted repositories contain sensitive data.",
        immediate_steps=[
            "1. Revoke the fine-grained token at GitHub Settings → Developer settings → Fine-grained tokens",
            "2. Check audit log for unauthorized access to the affected repositories",
            "3. Rotate any integrations that used this token",
        ],
        revoke_urls=["https://github.com/settings/tokens?type=beta"],
        git_cleanup_command="N/A — revoke token directly.",
        prevention_tips=[
            "Use GitHub Actions with OIDC for CI/CD instead of PATs",
            "Set short expiration periods (30 days)",
            "Review token permissions regularly",
        ],
    ),
    "GitHub App Token": RemediationInfo(
        risk="Installation access token for a GitHub App. Can access repositories the app is installed on.",
        severity_reason="Can provide API access to multiple repositories depending on app installation scope.",
        immediate_steps=[
            "1. Revoke the app installation or regenerate the token in GitHub App settings",
            "2. Check audit log for unauthorized access",
            "3. Notify the GitHub App owner to rotate their app secrets",
        ],
        revoke_urls=["https://github.com/settings/apps"],
        git_cleanup_command="N/A — revoke token directly.",
        prevention_tips=["Use short-lived installation tokens", "Limit app repository access to only what's necessary"],
    ),
    "Slack Webhook": RemediationInfo(
        risk="Attacker can send messages to your Slack channels, impersonate your services, phish your team, or exfiltrate data via Slack.",
        severity_reason="Incoming webhooks can post to channels without restriction. Attackers use them for social engineering and data exfiltration.",
        immediate_steps=[
            "1. Delete the compromised webhook in Slack API dashboard",
            "2. Create a new webhook URL and update all services that use it",
            "3. Review channel history for any unauthorized messages",
            "4. Consider switching to Slack apps with more granular permissions",
        ],
        revoke_urls=["https://api.slack.com/apps"],
        git_cleanup_command="bfg --replace-text webhooks.txt <repository>.git",
        prevention_tips=[
            "Store webhook URLs in environment variables or secret managers",
            "Use Slack apps with specific channel permissions instead of legacy webhooks",
            "Rotate webhook URLs periodically",
        ],
    ),
    "Slack Token": RemediationInfo(
        risk="Full API access to your Slack workspace. Attacker can read all messages, send messages as any user, access files, and perform administrative actions.",
        severity_reason="Slack tokens often have broad scopes including channels:history, chat:write, and files:read.",
        immediate_steps=[
            "1. Immediately revoke the token at https://api.slack.com/apps",
            "2. Review workspace audit logs for unauthorized access",
            "3. Rotate the token and update all integrations",
            "4. Review token scopes to understand the blast radius",
        ],
        revoke_urls=["https://api.slack.com/apps"],
        git_cleanup_command="bfg --replace-text tokens.txt <repository>.git",
        prevention_tips=[
            "Use the minimum required scopes for your Slack app",
            "Never commit tokens to repositories",
            "Use Slack's granular bot token permissions",
        ],
    ),
    "Stripe Live Key": RemediationInfo(
        risk="Attacker can process refunds, create charges, access customer data, and modify your Stripe account. Financial and PCI compliance risk.",
        severity_reason="Live keys provide real financial access. Attacker can steal money, customer PII, and cause irreversible financial damage.",
        immediate_steps=[
            "1. Immediately roll the compromised key in Stripe Dashboard",
            "2. Review recent charges, refunds, and transfers for fraudulent activity",
            "3. Check the Stripe audit log for unauthorized API calls",
            "4. Notify Stripe support if you suspect fraudulent activity",
            "5. Update all services that use this key with the new key",
        ],
        revoke_urls=["https://dashboard.stripe.com/apikeys"],
        git_cleanup_command="bfg --replace-text keys.txt <repository>.git",
        prevention_tips=[
            "Use restricted API keys with minimal permissions",
            "Rotate keys every 90 days",
            "Store keys in environment variables or Stripe's secret store",
            "Never commit test keys either (they can be used for reconnaissance)",
        ],
        reference_urls=["https://stripe.com/docs/keys"],
    ),
    "Stripe Test Key": RemediationInfo(
        risk="Lower risk (test mode), but still reveals your Stripe account structure and can be used for reconnaissance.",
        severity_reason="Test keys don't access real data, but expose your test environment which can aid targeted attacks.",
        immediate_steps=[
            "1. Roll the test key in Stripe Dashboard",
            "2. Review test mode data for any sensitive information",
        ],
        revoke_urls=["https://dashboard.stripe.com/apikeys"],
        git_cleanup_command="bfg --replace-text keys.txt <repository>.git",
        prevention_tips=["Still treat test keys as sensitive", "Use separate test accounts for different environments"],
    ),
    "Stripe Webhook Secret": RemediationInfo(
        risk="Attacker can send forged webhook events to your application, triggering fake payment confirmations or other state changes.",
        severity_reason="Webhook secrets verify the authenticity of Stripe events. A compromised secret enables event forgery.",
        immediate_steps=[
            "1. Roll the webhook signing secret in Stripe Dashboard",
            "2. Verify your endpoint received only legitimate events (check timestamps)",
            "3. Update the secret in your application's configuration",
        ],
        revoke_urls=["https://dashboard.stripe.com/webhooks"],
        git_cleanup_command="bfg --replace-text webhook-secrets.txt <repository>.git",
        prevention_tips=["Store webhook secrets in environment variables", "Rotate webhook secrets periodically"],
    ),
    "Google API Key": RemediationInfo(
        risk="Attacker can use your API key against Google services (Maps, YouTube, Translate, etc.), potentially incurring significant costs and bypassing your quotas.",
        severity_reason="Unrestricted API keys can be used by anyone. Even restricted keys may leak usage context.",
        immediate_steps=[
            "1. Regenerate the API key in Google Cloud Console",
            "2. Restrict the old key immediately (limit to specific APIs and IPs/HTTP referrers)",
            "3. Review Cloud Billing reports for unauthorized usage",
            "4. Update all applications with the new key",
        ],
        revoke_urls=["https://console.cloud.google.com/apis/credentials"],
        git_cleanup_command="bfg --replace-text keys.txt <repository>.git",
        prevention_tips=[
            "Restrict API keys to specific APIs and allowed IPs/referrers",
            "Use OAuth 2.0 instead of API keys where possible",
            "Monitor API key usage in Google Cloud Console",
        ],
        reference_urls=["https://cloud.google.com/docs/authentication/api-keys"],
    ),
    "Google OAuth Client ID": RemediationInfo(
        risk="Client ID alone is less dangerous (it's semi-public), but combined with a client secret (also commonly nearby) gives OAuth access.",
        severity_reason="Often committed alongside the client secret. Together they allow OAuth 2.0 authentication as your application.",
        immediate_steps=[
            "1. If client secret is also exposed, immediately revoke both in Google Cloud Console",
            "2. If only client ID, verify no secret is exposed in the same file or nearby commits",
            "3. Create new OAuth 2.0 credentials and update your application",
        ],
        revoke_urls=["https://console.cloud.google.com/apis/credentials"],
        git_cleanup_command="bfg --replace-text credentials.txt <repository>.git",
        prevention_tips=[
            "Never commit OAuth credentials to source control",
            "Use environment variables for all OAuth secrets",
            "Set up application restriction on OAuth 2.0 Client IDs",
        ],
    ),
    "SendGrid API Key": RemediationInfo(
        risk="Attacker can send emails from your domain, damage your sender reputation, phish your users, and exhaust your email quota.",
        severity_reason="SendGrid keys allow sending unlimited emails. Reputation damage is costly and takes months to repair.",
        immediate_steps=[
            "1. Revoke the compromised API key in SendGrid Dashboard",
            "2. Generate a new API key and update your email services",
            "3. Check SendGrid activity logs for unauthorized email sends",
            "4. Review your sender reputation on postmaster tools",
        ],
        revoke_urls=["https://app.sendgrid.com/settings/api_keys"],
        git_cleanup_command="bfg --replace-text keys.txt <repository>.git",
        prevention_tips=[
            "Use sub-user API keys with limited permissions",
            "Set up IP allowlisting for API keys",
            "Monitor email activity for unusual patterns",
        ],
    ),
    "Twilio API Key": RemediationInfo(
        risk="Attacker can send SMS messages, make phone calls, access call logs, and incur massive telephony charges.",
        severity_reason="Twilio keys provide direct access to telephony services. Automated attacks can rack up thousands in charges quickly.",
        immediate_steps=[
            "1. Revoke the compromised API key in Twilio Console",
            "2. Check usage logs for unauthorized SMS/calls",
            "3. Update all applications using this key",
            "4. Set up spending limits and alerts in Twilio",
        ],
        revoke_urls=["https://console.twilio.com/?frameUrl=/console/api-keys"],
        git_cleanup_command="bfg --replace-text keys.txt <repository>.git",
        prevention_tips=[
            "Use API keys with minimal permissions (e.g., send-only)",
            "Set up spending limits and anomaly alerts",
            "Use Twilio Functions for serverless execution instead of exposing keys",
        ],
    ),
    "Twilio Account SID": RemediationInfo(
        risk="Account SID is semi-public but essential for API access. Combined with auth token (often nearby), this gives full account access.",
        severity_reason="Similar to Google Client ID — dangerous when accompanied by the auth token which is often in the same file.",
        immediate_steps=[
            "1. If auth token is also exposed, revoke and regenerate immediately in Twilio Console",
            "2. Rotate both the Account SID reference and auth token in all applications",
            "3. Review account activity for unauthorized usage",
        ],
        revoke_urls=["https://console.twilio.com"],
        git_cleanup_command="bfg --replace-text credentials.txt <repository>.git",
        prevention_tips=["Store Twilio credentials in environment variables", "Use Twilio's API key authentication instead of Account SID + Auth Token"],
    ),
    "SSH Private Key": RemediationInfo(
        risk="Attacker can authenticate as you to any server that has your public key. Full server access, data exfiltration, and lateral movement within your infrastructure.",
        severity_reason="Worst-case scenario. Can lead to complete infrastructure compromise if this key is used for server access.",
        immediate_steps=[
            "1. Remove the compromised public key from all servers' authorized_keys files immediately",
            "2. Generate a new SSH key pair (ssh-keygen -t ed25519)",
            "3. Deploy the new public key to all servers",
            "4. Check server auth logs for any unauthorized SSH sessions",
            "5. If key had a passphrase, assume it's compromised and rotate any credentials accessible from sessions",
        ],
        revoke_urls=["N/A — server-side removal required. Check each server's ~/.ssh/authorized_keys"],
        git_cleanup_command="bfg --delete-files '*.pem' --delete-files '*.key' <repository>.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive",
        prevention_tips=[
            "Never commit private keys to any repository",
            "Use SSH certificates instead of key pairs for infrastructure access",
            "Use a SSH agent with forwarding instead of distributing private keys",
            "Add *.key and *.pem to .gitignore",
        ],
        reference_urls=["https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key"],
    ),
    "PGP Private Key": RemediationInfo(
        risk="Attacker can sign code/emails as you, decrypt any messages encrypted with your public key, and impersonate you in communications.",
        severity_reason="PGP keys are used for identity verification, code signing, and encryption. Compromise undermines trust in your identity.",
        immediate_steps=[
            "1. Revoke the compromised PGP key using a revocation certificate",
            "2. Publish the revocation certificate to keyservers",
            "3. Generate a new PGP key pair and distribute the new public key",
            "4. Re-sign any previously signed artifacts with the new key",
            "5. Notify contacts that your old key is compromised",
        ],
        revoke_urls=["N/A — use gpg --gen-revoke <key-id> to generate a revocation certificate"],
        git_cleanup_command="bfg --delete-files '*.asc' --delete-files '*.gpg' <repository>.git",
        prevention_tips=[
            "Store PGP private keys on hardware security keys (YubiKey)",
            "Never export private keys to files",
            "Set a strong passphrase on all PGP keys",
        ],
    ),
    "PostgreSQL URL": RemediationInfo(
        risk="Direct database access. Attacker can read, modify, and delete all data in your PostgreSQL databases.",
        severity_reason="Database URLs contain plaintext credentials. Provides read/write access to your production data.",
        immediate_steps=[
            "1. Immediately rotate the database password",
            "2. Update all applications with the new password",
            "3. Review database logs for unauthorized queries since commit",
            "4. Check for any data exfiltration (unusual query patterns, large result sets)",
            "5. Ensure database is not publicly accessible (restrict to trusted IPs)",
        ],
        revoke_urls=["N/A — rotate password via your database management console"],
        git_cleanup_command="bfg --replace-text database-urls.txt <repository>.git",
        prevention_tips=[
            "Use IAM-based database authentication instead of passwords",
            "Never commit connection strings to source control",
            "Use environment variables or a secrets manager for database URLs",
            "Restrict database access to specific IP ranges and VPCs",
        ],
    ),
    "MySQL URL": RemediationInfo(
        risk="Direct database access to MySQL/MariaDB. Attacker can exfiltrate, modify, or delete all data.",
        severity_reason="Contains plaintext username and password for production database access.",
        immediate_steps=[
            "1. Rotate the database password immediately",
            "2. Update connection strings in all applications",
            "3. Audit MySQL general log for unauthorized queries",
            "4. Restrict MySQL access to trusted IPs/VPC",
        ],
        revoke_urls=["N/A — rotate password via MySQL ALTER USER command"],
        git_cleanup_command="bfg --replace-text database-urls.txt <repository>.git",
        prevention_tips=[
            "Use AWS RDS IAM authentication or similar",
            "Store database credentials in secrets managers",
            "Use SSL/TLS for all database connections",
        ],
    ),
    "MongoDB URL": RemediationInfo(
        risk="Direct MongoDB database access. Attacker can read, modify, or delete documents, collections, and databases.",
        severity_reason="Plaintext credentials in MongoDB connection string. Often provides full read/write access.",
        immediate_steps=[
            "1. Rotate the database password",
            "2. Update all applications with new connection string",
            "3. Review MongoDB logs for suspicious queries",
            "4. Ensure MongoDB access list is restricted to trusted IPs",
            "5. Enable MongoDB audit logging if not already enabled",
        ],
        revoke_urls=["N/A — rotate password via MongoDB Atlas or database admin"],
        git_cleanup_command="bfg --replace-text database-urls.txt <repository>.git",
        prevention_tips=[
            "Use MongoDB Atlas IP access lists",
            "Enable database authentication with SCRAM",
            "Store connection strings in environment variables or secrets manager",
            "Use VPC peering instead of public endpoints",
        ],
    ),
    "Redis URL": RemediationInfo(
        risk="Direct Redis database access. Attacker can read cached data, session tokens, and potentially pivot to other systems.",
        severity_reason="Redis often contains session data, cached credentials, and job queues. Unauthorized access can lead to data breach.",
        immediate_steps=[
            "1. Rotate the Redis password immediately",
            "2. Update all applications with new password",
            "3. Review Redis MONITOR logs if available",
            "4. Ensure Redis is bound to localhost or VPC (never 0.0.0.0)",
            "5. Enable Redis AUTH and TLS",
        ],
        revoke_urls=["N/A — use CONFIG SET requirepass or update Redis config"],
        git_cleanup_command="bfg --replace-text redis-urls.txt <repository>.git",
        prevention_tips=[
            "Never expose Redis to the internet",
            "Use Redis over TLS with password authentication",
            "Store Redis credentials in secrets manager",
        ],
    ),
    "JWT Token": RemediationInfo(
        risk="If this is a valid JWT, attacker can impersonate the user/application the token belongs to. If the JWT includes secrets in its payload, those are also exposed.",
        severity_reason="JWTs often contain authentication state. Valid unexpired tokens grant immediate access. Secret keys embedded in JWTs are game-over.",
        immediate_steps=[
            "1. If this is a JWT secret key (not just a token), regenerate it immediately",
            "2. If this is a session JWT, revoke it by adding to a deny list or rotating the signing key",
            "3. Check JWT expiration — if unexpired, assume it's been used maliciously",
            "4. Rotate the JWT signing secret and reissue tokens to all legitimate users",
        ],
        revoke_urls=["N/A — depends on your auth provider. Revoke at your identity provider."],
        git_cleanup_command="bfg --replace-text jwt-secrets.txt <repository>.git",
        prevention_tips=[
            "Never embed JWT signing secrets in source code",
            "Use short token expiration times (15 minutes for access tokens)",
            "Use refresh tokens for long-lived sessions",
            "Store JWTs in secure HTTP-only cookies, not in source",
        ],
    ),
    "NPM Token": RemediationInfo(
        risk="Attacker can publish packages under your name, unpublish existing packages, or access private packages.",
        severity_reason="NPM tokens control package publishing. Supply chain attacks via malicious packages can affect thousands of downstream projects.",
        immediate_steps=[
            "1. Revoke the token at https://www.npmjs.com/settings/tokens",
            "2. Review recent package publications for unauthorized releases",
            "3. Enable two-factor authentication on your npm account",
            "4. Rotate all npm tokens",
        ],
        revoke_urls=["https://www.npmjs.com/settings/tokens"],
        git_cleanup_command="bfg --replace-text tokens.txt <repository>.git",
        prevention_tips=[
            "Use granular automation tokens with limited scope",
            "Never commit .npmrc files with tokens",
            "Use npm token rotation policies",
            "Enable 2FA on npm accounts",
        ],
    ),
    "PyPI Token": RemediationInfo(
        risk="Attacker can publish malicious packages under your name, compromising all users who pip install your packages.",
        severity_reason="Supply chain attack vector. One compromised PyPI token can lead to thousands of infected systems.",
        immediate_steps=[
            "1. Revoke the token at https://pypi.org/manage/account/token/",
            "2. Check recent project releases for unauthorized uploads",
            "3. Rotate all API tokens",
            "4. Enable two-factor authentication on your PyPI account",
        ],
        revoke_urls=["https://pypi.org/manage/account/token/"],
        git_cleanup_command="bfg --replace-text tokens.txt <repository>.git",
        prevention_tips=[
            "Use trusted publishing (OIDC) instead of API tokens for CI/CD",
            "Use per-project tokens with limited scopes",
            "Enable 2FA on PyPI accounts",
        ],
    ),
    "Bearer Token (in code)": RemediationInfo(
        risk="Direct API access to whatever service the bearer token authenticates to. Scope depends on the token's permissions.",
        severity_reason="Bearer tokens are used for API authentication. They grant immediate access without additional verification.",
        immediate_steps=[
            "1. Identify the token format and revoke it at the issuing service",
            "2. Generate a new token and update all applications",
            "3. Review audit logs for unauthorized API calls",
        ],
        revoke_urls=["N/A — depends on the token issuer. Check your auth provider's dashboard."],
        git_cleanup_command="bfg --replace-text tokens.txt <repository>.git",
        prevention_tips=[
            "Use short-lived tokens (minutes, not days)",
            "Use OAuth 2.0 client credentials flow with automatic rotation",
            "Never hardcode bearer tokens in source code",
        ],
    ),
    "Private Key in Variable": RemediationInfo(
        risk="Full private key exposure. Same severity as SSH/PGP private keys. Attacker can authenticate as the key owner.",
        severity_reason="Private keys assigned to variables in code are typically used for server access, code signing, or encryption.",
        immediate_steps=[
            "1. Determine what system this key authenticates to",
            "2. Revoke the key on all systems that recognize its public key",
            "3. Generate a new key pair and deploy securely",
            "4. Remove the key from all git history",
        ],
        revoke_urls=["N/A — server-side revocation required"],
        git_cleanup_command="bfg --delete-files '*.pem' --delete-files '*.key' <repository>.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive",
        prevention_tips=["Never assign private keys to variables in code", "Use a secrets manager or hardware security module"],
    ),
    "High-Entropy String": RemediationInfo(
        risk="Could be an API key, password, or cryptographic secret in a custom format that doesn't match known patterns. Requires manual investigation.",
        severity_reason="High entropy indicates randomness typical of cryptographic keys, tokens, and passwords.",
        immediate_steps=[
            "1. Investigate the context — check what service or system this string belongs to",
            "2. If confirmed as a secret, revoke and rotate it immediately",
            "3. Add the secret format to custom regex patterns for future detection",
            "4. If determined to be a false positive, add to custom whitelist",
        ],
        revoke_urls=["N/A — depends on the specific secret identified"],
        git_cleanup_command="bfg --replace-text secrets.txt <repository>.git. If confirmed, follow specific revocation steps for the identified service.",
        prevention_tips=[
            "Audit all high-entropy findings manually to classify them",
            "Use a consistent naming convention for secret variables (SECRET_, API_KEY_)",
            "Add confirmed secret patterns to the custom regex library",
            "Use structured secrets management (Vault, AWS Secrets Manager, etc.)",
        ],
    ),
}


def get_remediation(secret_type: str) -> RemediationInfo | None:
    return _REMEDIATION_MAP.get(secret_type)
