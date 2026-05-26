from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)

SENSITIVE_PATHS: list[dict] = [
    # ── Universal: credentials & secrets ─────────────────────────────────────
    {"path": "/.env",                       "severity": "Critical", "name": ".env credentials exposed",          "stack": "universal"},
    {"path": "/.env.local",                 "severity": "Critical", "name": ".env.local exposed",                "stack": "universal"},
    {"path": "/.env.production",            "severity": "Critical", "name": ".env.production exposed",           "stack": "universal"},
    {"path": "/.env.staging",               "severity": "Critical", "name": ".env.staging exposed",              "stack": "universal"},
    {"path": "/.env.backup",                "severity": "Critical", "name": ".env.backup exposed",               "stack": "universal"},
    {"path": "/.env.example",               "severity": "Low",      "name": ".env.example exposed",              "stack": "universal"},
    {"path": "/credentials.json",           "severity": "Critical", "name": "credentials.json exposed",          "stack": "universal"},
    {"path": "/secrets.json",               "severity": "Critical", "name": "secrets.json exposed",              "stack": "universal"},
    {"path": "/secrets.yaml",               "severity": "Critical", "name": "secrets.yaml exposed",              "stack": "universal"},
    {"path": "/secrets.yml",                "severity": "Critical", "name": "secrets.yml exposed",               "stack": "universal"},

    # ── Universal: VCS ────────────────────────────────────────────────────────
    {"path": "/.git/config",                "severity": "High",     "name": "Git repository config exposed",     "stack": "universal"},
    {"path": "/.git/HEAD",                  "severity": "High",     "name": "Git HEAD ref exposed",              "stack": "universal"},
    {"path": "/.gitignore",                 "severity": "Low",      "name": ".gitignore exposed (reveals paths)","stack": "universal"},
    {"path": "/.svn/entries",               "severity": "High",     "name": "SVN repository exposed",            "stack": "universal"},
    {"path": "/.hg/store/00manifest.i",     "severity": "High",     "name": "Mercurial repo exposed",            "stack": "universal"},

    # ── Universal: editor / IDE artifacts ────────────────────────────────────
    {"path": "/.DS_Store",                  "severity": "Low",      "name": ".DS_Store leak (directory listing)","stack": "universal"},
    {"path": "/.vscode/settings.json",      "severity": "Low",      "name": "VSCode settings exposed",           "stack": "universal"},
    {"path": "/.idea/workspace.xml",        "severity": "Low",      "name": "JetBrains workspace exposed",       "stack": "universal"},

    # ── Universal: backups & dumps ────────────────────────────────────────────
    {"path": "/backup.sql",                 "severity": "Critical", "name": "SQL backup exposed",                "stack": "universal"},
    {"path": "/dump.sql",                   "severity": "Critical", "name": "SQL dump exposed",                  "stack": "universal"},
    {"path": "/db.sql",                     "severity": "Critical", "name": "SQL dump exposed",                  "stack": "universal"},
    {"path": "/database.sql",               "severity": "Critical", "name": "SQL dump exposed",                  "stack": "universal"},
    {"path": "/backup.zip",                 "severity": "High",     "name": "Backup archive exposed",            "stack": "universal"},
    {"path": "/backup.tar.gz",              "severity": "High",     "name": "Backup archive exposed",            "stack": "universal"},
    {"path": "/site.zip",                   "severity": "High",     "name": "Site archive exposed",              "stack": "universal"},
    {"path": "/www.zip",                    "severity": "High",     "name": "Site archive exposed",              "stack": "universal"},

    # ── Universal: log files ──────────────────────────────────────────────────
    {"path": "/error.log",                  "severity": "Medium",   "name": "Error log exposed",                 "stack": "universal"},
    {"path": "/access.log",                 "severity": "Medium",   "name": "Access log exposed",                "stack": "universal"},
    {"path": "/debug.log",                  "severity": "Medium",   "name": "Debug log exposed",                 "stack": "universal"},
    {"path": "/app.log",                    "severity": "Medium",   "name": "Application log exposed",           "stack": "universal"},
    {"path": "/logs/error.log",             "severity": "Medium",   "name": "Error log exposed",                 "stack": "universal"},

    # ── Universal: API & docs ─────────────────────────────────────────────────
    {"path": "/graphql",                    "severity": "Low",      "name": "GraphQL endpoint exposed",          "stack": "universal"},
    {"path": "/graphiql",                   "severity": "Medium",   "name": "GraphiQL IDE exposed",              "stack": "universal"},
    {"path": "/graphql/console",            "severity": "Medium",   "name": "GraphQL console exposed",           "stack": "universal"},
    {"path": "/graphql/playground",         "severity": "Medium",   "name": "GraphQL playground exposed",        "stack": "universal"},
    {"path": "/__graphql",                  "severity": "Low",      "name": "GraphQL endpoint exposed",          "stack": "universal"},
    {"path": "/api/graphql",                "severity": "Low",      "name": "GraphQL API endpoint exposed",      "stack": "universal"},
    {"path": "/swagger",                    "severity": "Low",      "name": "Swagger UI exposed",                "stack": "universal"},
    {"path": "/swagger-ui.html",            "severity": "Low",      "name": "Swagger UI exposed",                "stack": "universal"},
    {"path": "/api-docs",                   "severity": "Low",      "name": "API docs exposed",                  "stack": "universal"},
    {"path": "/v2/api-docs",                "severity": "Low",      "name": "Swagger v2 API docs exposed",       "stack": "universal"},
    {"path": "/v3/api-docs",                "severity": "Low",      "name": "OpenAPI v3 docs exposed",           "stack": "universal"},
    {"path": "/openapi.json",               "severity": "Low",      "name": "OpenAPI spec exposed",              "stack": "universal"},
    {"path": "/openapi.yaml",               "severity": "Low",      "name": "OpenAPI spec exposed",              "stack": "universal"},
    {"path": "/server-status",              "severity": "Medium",   "name": "Apache server-status exposed",      "stack": "universal"},
    {"path": "/server-info",                "severity": "Medium",   "name": "Apache server-info exposed",        "stack": "universal"},
    {"path": "/nginx_status",               "severity": "Low",      "name": "Nginx stub_status exposed",         "stack": "universal"},
    {"path": "/metrics",                    "severity": "Low",      "name": "Prometheus metrics exposed",        "stack": "universal"},
    {"path": "/robots.txt",                 "severity": "Low",      "name": "robots.txt exposed (check Disallow paths)", "stack": "universal"},
    {"path": "/sitemap.xml",                "severity": "Low",      "name": "sitemap.xml exposed (path enumeration)", "stack": "universal"},
    {"path": "/.htpasswd",                  "severity": "Critical", "name": ".htpasswd exposed (hashed credentials)", "stack": "universal"},
    {"path": "/.htaccess",                  "severity": "Medium",   "name": ".htaccess exposed (URL rewrite rules)", "stack": "universal"},
    {"path": "/crossdomain.xml",            "severity": "Low",      "name": "crossdomain.xml exposed",           "stack": "universal"},
    {"path": "/wsdl",                       "severity": "Low",      "name": "SOAP WSDL descriptor exposed",      "stack": "universal"},

    # ── PHP / WordPress / Laravel / Symfony ───────────────────────────────────
    {"path": "/phpinfo.php",                "severity": "High",     "name": "phpinfo() page exposed",            "stack": "php"},
    {"path": "/info.php",                   "severity": "High",     "name": "PHP info page exposed",             "stack": "php"},
    {"path": "/test.php",                   "severity": "Medium",   "name": "test.php exposed",                  "stack": "php"},
    {"path": "/debug.php",                  "severity": "High",     "name": "debug.php exposed",                 "stack": "php"},
    {"path": "/wp-config.php.bak",          "severity": "Critical", "name": "WordPress config backup exposed",   "stack": "wordpress"},
    {"path": "/wp-config.php~",             "severity": "Critical", "name": "WordPress config backup exposed",   "stack": "wordpress"},
    {"path": "/wp-config.txt",              "severity": "Critical", "name": "WordPress config txt exposed",      "stack": "wordpress"},
    {"path": "/phpmyadmin",                 "severity": "High",     "name": "phpMyAdmin exposed",                "stack": "php"},
    {"path": "/pma",                        "severity": "High",     "name": "phpMyAdmin (pma) exposed",          "stack": "php"},
    {"path": "/adminer.php",                "severity": "High",     "name": "Adminer DB tool exposed",           "stack": "php"},
    {"path": "/_profiler",                  "severity": "Medium",   "name": "Symfony profiler exposed",          "stack": "php"},
    {"path": "/__debugbar",                 "severity": "Medium",   "name": "Laravel debugbar exposed",          "stack": "php"},
    {"path": "/telescope",                  "severity": "Medium",   "name": "Laravel Telescope exposed",         "stack": "php"},
    {"path": "/horizon",                    "severity": "Medium",   "name": "Laravel Horizon exposed",           "stack": "php"},
    {"path": "/storage/logs/laravel.log",   "severity": "Medium",   "name": "Laravel log exposed",               "stack": "php"},
    {"path": "/config/database.yml",        "severity": "Critical", "name": "Database config exposed",           "stack": "php"},
    {"path": "/config.php.bak",             "severity": "Critical", "name": "PHP config backup exposed",         "stack": "php"},

    # ── Python (Django / Flask) ───────────────────────────────────────────────
    {"path": "/settings.py",               "severity": "Critical", "name": "Django settings.py exposed",        "stack": "python"},
    {"path": "/config.py",                 "severity": "Critical", "name": "Python config exposed",             "stack": "python"},
    {"path": "/local_settings.py",         "severity": "Critical", "name": "Django local settings exposed",     "stack": "python"},
    {"path": "/requirements.txt",          "severity": "Low",      "name": "requirements.txt exposed",          "stack": "python"},
    {"path": "/Pipfile",                   "severity": "Low",      "name": "Pipfile exposed",                   "stack": "python"},
    {"path": "/pyproject.toml",            "severity": "Low",      "name": "pyproject.toml exposed",            "stack": "python"},
    {"path": "/__pycache__/",              "severity": "Medium",   "name": "Python __pycache__ exposed",        "stack": "python"},
    {"path": "/celeryconfig.py",           "severity": "High",     "name": "Celery config exposed",             "stack": "python"},
    {"path": "/wsgi.py",                   "severity": "Medium",   "name": "WSGI config exposed",               "stack": "python"},
    {"path": "/manage.py",                 "severity": "Medium",   "name": "Django manage.py exposed",          "stack": "python"},

    # ── Node.js (Express / Next.js / NestJS) ─────────────────────────────────
    {"path": "/package.json",              "severity": "Low",      "name": "package.json exposed (dep list)",   "stack": "nodejs"},
    {"path": "/package-lock.json",         "severity": "Low",      "name": "package-lock.json exposed",         "stack": "nodejs"},
    {"path": "/yarn.lock",                 "severity": "Low",      "name": "yarn.lock exposed",                 "stack": "nodejs"},
    {"path": "/pnpm-lock.yaml",            "severity": "Low",      "name": "pnpm-lock.yaml exposed",            "stack": "nodejs"},
    {"path": "/node_modules/.package-lock.json","severity":"Medium","name": "node_modules exposed",             "stack": "nodejs"},
    {"path": "/.npmrc",                    "severity": "High",     "name": ".npmrc exposed (may contain token)","stack": "nodejs"},
    {"path": "/.nvmrc",                    "severity": "Low",      "name": ".nvmrc exposed",                    "stack": "nodejs"},
    {"path": "/next.config.js",            "severity": "Low",      "name": "Next.js config exposed",            "stack": "nodejs"},
    {"path": "/nest-cli.json",             "severity": "Low",      "name": "NestJS config exposed",             "stack": "nodejs"},
    {"path": "/webpack.config.js",         "severity": "Low",      "name": "Webpack config exposed",            "stack": "nodejs"},

    # ── Ruby on Rails ─────────────────────────────────────────────────────────
    {"path": "/config/database.yml",       "severity": "Critical", "name": "Rails database.yml exposed",        "stack": "ruby"},
    {"path": "/config/secrets.yml",        "severity": "Critical", "name": "Rails secrets.yml exposed",         "stack": "ruby"},
    {"path": "/config/credentials.yml.enc","severity": "High",     "name": "Rails encrypted credentials exposed","stack": "ruby"},
    {"path": "/Gemfile",                   "severity": "Low",      "name": "Gemfile exposed",                   "stack": "ruby"},
    {"path": "/Gemfile.lock",              "severity": "Low",      "name": "Gemfile.lock exposed",              "stack": "ruby"},
    {"path": "/log/production.log",        "severity": "Medium",   "name": "Rails production log exposed",      "stack": "ruby"},
    {"path": "/log/development.log",       "severity": "Low",      "name": "Rails development log exposed",     "stack": "ruby"},

    # ── Java / Spring Boot ────────────────────────────────────────────────────
    {"path": "/actuator",                  "severity": "High",     "name": "Spring Actuator exposed",           "stack": "java"},
    {"path": "/actuator/env",              "severity": "Critical", "name": "Spring Actuator /env exposed",      "stack": "java"},
    {"path": "/actuator/health",           "severity": "Low",      "name": "Spring Actuator /health exposed",   "stack": "java"},
    {"path": "/actuator/beans",            "severity": "Medium",   "name": "Spring Actuator /beans exposed",    "stack": "java"},
    {"path": "/actuator/logfile",          "severity": "Medium",   "name": "Spring Actuator /logfile exposed",  "stack": "java"},
    {"path": "/application.properties",   "severity": "Critical", "name": "Spring application.properties exposed","stack": "java"},
    {"path": "/application.yml",           "severity": "Critical", "name": "Spring application.yml exposed",    "stack": "java"},
    {"path": "/WEB-INF/web.xml",           "severity": "High",     "name": "Java WEB-INF web.xml exposed",      "stack": "java"},
    {"path": "/META-INF/MANIFEST.MF",      "severity": "Medium",   "name": "Java MANIFEST.MF exposed",          "stack": "java"},

    # ── .NET / ASP.NET ────────────────────────────────────────────────────────
    {"path": "/web.config",                "severity": "Critical", "name": "ASP.NET web.config exposed",        "stack": "dotnet"},
    {"path": "/appsettings.json",          "severity": "Critical", "name": "ASP.NET appsettings.json exposed",  "stack": "dotnet"},
    {"path": "/appsettings.Production.json","severity":"Critical", "name": "ASP.NET production settings exposed","stack": "dotnet"},
    {"path": "/appsettings.Development.json","severity":"High",    "name": "ASP.NET dev settings exposed",      "stack": "dotnet"},
    {"path": "/elmah.axd",                 "severity": "High",     "name": "ELMAH error log exposed",           "stack": "dotnet"},
    {"path": "/trace.axd",                 "severity": "High",     "name": "ASP.NET Trace exposed",             "stack": "dotnet"},

    # ── Go ────────────────────────────────────────────────────────────────────
    {"path": "/go.mod",                    "severity": "Low",      "name": "go.mod exposed",                    "stack": "go"},
    {"path": "/go.sum",                    "severity": "Low",      "name": "go.sum exposed",                    "stack": "go"},
    {"path": "/config.yaml",               "severity": "High",     "name": "config.yaml exposed",               "stack": "go"},
    {"path": "/config.yml",                "severity": "High",     "name": "config.yml exposed",                "stack": "go"},

    # ── DevOps / Cloud / CI ───────────────────────────────────────────────────
    {"path": "/.github/workflows/deploy.yml","severity":"Low",     "name": "GitHub Actions deploy workflow exposed","stack": "devops"},
    {"path": "/.travis.yml",               "severity": "Low",      "name": ".travis.yml exposed",               "stack": "devops"},
    {"path": "/Dockerfile",                "severity": "Low",      "name": "Dockerfile exposed",                "stack": "devops"},
    {"path": "/docker-compose.yml",        "severity": "Medium",   "name": "docker-compose.yml exposed",        "stack": "devops"},
    {"path": "/docker-compose.yaml",       "severity": "Medium",   "name": "docker-compose.yml exposed",        "stack": "devops"},
    {"path": "/Jenkinsfile",               "severity": "Low",      "name": "Jenkinsfile exposed",               "stack": "devops"},
    {"path": "/terraform.tfvars",          "severity": "Critical", "name": "Terraform vars (secrets) exposed",  "stack": "devops"},
    {"path": "/.aws/credentials",          "severity": "Critical", "name": "AWS credentials exposed",           "stack": "devops"},
    {"path": "/serverless.yml",            "severity": "Medium",   "name": "Serverless config exposed",         "stack": "devops"},
    {"path": "/ansible.cfg",               "severity": "Medium",   "name": "Ansible config exposed",            "stack": "devops"},

    # ── VCS: additional Git paths ─────────────────────────────────────────────
    {"path": "/.git/logs/HEAD",            "severity": "High",     "name": "Git commit log exposed",            "stack": "universal"},
    {"path": "/.git/COMMIT_EDITMSG",       "severity": "Medium",   "name": "Git commit message exposed",        "stack": "universal"},
    {"path": "/.git/packed-refs",          "severity": "Medium",   "name": "Git packed-refs exposed",           "stack": "universal"},
    {"path": "/.git/index",                "severity": "High",     "name": "Git index (file list) exposed",     "stack": "universal"},
    {"path": "/CVS/Root",                  "severity": "High",     "name": "CVS repository exposed",            "stack": "universal"},

    # ── Cloud / IaC ───────────────────────────────────────────────────────────
    {"path": "/terraform.tfstate",         "severity": "Critical", "name": "Terraform state file exposed",      "stack": "devops"},
    {"path": "/terraform.tfstate.backup",  "severity": "Critical", "name": "Terraform state backup exposed",   "stack": "devops"},
    {"path": "/.kube/config",              "severity": "Critical", "name": "Kubernetes config exposed",         "stack": "devops"},
    {"path": "/.aws/config",               "severity": "High",     "name": "AWS config exposed",               "stack": "devops"},
    {"path": "/service-account.json",      "severity": "Critical", "name": "GCP service account key exposed",   "stack": "devops"},
    {"path": "/key.json",                  "severity": "Critical", "name": "GCP service account key exposed",   "stack": "devops"},
    {"path": "/client_secret.json",        "severity": "Critical", "name": "OAuth client secret exposed",       "stack": "devops"},
    {"path": "/firebase.json",             "severity": "High",     "name": "Firebase config exposed",           "stack": "devops"},
    {"path": "/.circleci/config.yml",      "severity": "Low",      "name": "CircleCI config exposed",          "stack": "devops"},
    {"path": "/.gitlab-ci.yml",            "severity": "Low",      "name": "GitLab CI config exposed",         "stack": "devops"},
    {"path": "/bitbucket-pipelines.yml",   "severity": "Low",      "name": "Bitbucket Pipelines config exposed","stack": "devops"},
    {"path": "/azure-pipelines.yml",       "severity": "Low",      "name": "Azure DevOps pipeline exposed",    "stack": "devops"},

    # ── Exposed private keys / credentials ───────────────────────────────────
    {"path": "/id_rsa",                    "severity": "Critical", "name": "SSH private key exposed",           "stack": "universal"},
    {"path": "/private.key",               "severity": "Critical", "name": "TLS private key exposed",           "stack": "universal"},
    {"path": "/server.key",                "severity": "Critical", "name": "TLS private key exposed",           "stack": "universal"},
    {"path": "/.netrc",                    "severity": "Critical", "name": ".netrc credentials file exposed",   "stack": "universal"},
    {"path": "/.pgpass",                   "severity": "Critical", "name": "PostgreSQL password file exposed",  "stack": "universal"},
    {"path": "/config/master.key",         "severity": "Critical", "name": "Rails master key exposed",          "stack": "ruby"},

    # ── Additional backup formats ─────────────────────────────────────────────
    {"path": "/backup.tar",                "severity": "High",     "name": "Backup archive exposed",            "stack": "universal"},
    {"path": "/backup.tgz",                "severity": "High",     "name": "Backup archive exposed",            "stack": "universal"},
    {"path": "/public_html.zip",           "severity": "High",     "name": "Site archive exposed",              "stack": "universal"},
    {"path": "/web.zip",                   "severity": "High",     "name": "Site archive exposed",              "stack": "universal"},
    {"path": "/web.config.bak",            "severity": "Critical", "name": "ASP.NET web.config backup exposed", "stack": "dotnet"},

    # ── Admin panels / monitoring UIs ─────────────────────────────────────────
    {"path": "/admin",                     "severity": "Low",      "name": "Admin panel accessible",            "stack": "universal"},
    {"path": "/admin/login",               "severity": "Low",      "name": "Admin login exposed",               "stack": "universal"},
    {"path": "/administrator",             "severity": "Low",      "name": "Joomla admin panel exposed",        "stack": "cms"},
    {"path": "/wp-admin",                  "severity": "Low",      "name": "WordPress admin exposed",           "stack": "wordpress"},
    {"path": "/manager/html",              "severity": "High",     "name": "Apache Tomcat Manager exposed",     "stack": "java"},
    {"path": "/host-manager/html",         "severity": "High",     "name": "Tomcat Host Manager exposed",       "stack": "java"},
    {"path": "/console",                   "severity": "High",     "name": "Admin console exposed",             "stack": "java"},
    {"path": "/grafana",                   "severity": "High",     "name": "Grafana dashboard exposed",         "stack": "devops"},
    {"path": "/kibana",                    "severity": "High",     "name": "Kibana dashboard exposed",          "stack": "devops"},
    {"path": "/solr/admin/",               "severity": "High",     "name": "Apache Solr admin exposed",         "stack": "java"},
    {"path": "/flower",                    "severity": "Medium",   "name": "Celery Flower UI exposed",          "stack": "python"},
    {"path": "/portainer/",                "severity": "High",     "name": "Portainer Docker UI exposed",       "stack": "devops"},
    {"path": "/prometheus/",               "severity": "Medium",   "name": "Prometheus UI exposed",             "stack": "devops"},
    {"path": "/pgadmin/",                  "severity": "High",     "name": "pgAdmin exposed",                   "stack": "devops"},
    {"path": "/mongo-express/",            "severity": "High",     "name": "MongoDB Express UI exposed",        "stack": "devops"},
    {"path": "/v1/sys/health",             "severity": "Low",      "name": "HashiCorp Vault health endpoint",   "stack": "devops"},
    {"path": "/actuator/configprops",      "severity": "Critical", "name": "Spring Actuator configprops exposed", "stack": "java"},
    {"path": "/actuator/mappings",         "severity": "Medium",   "name": "Spring Actuator URL mappings exposed", "stack": "java"},
    {"path": "/actuator/httptrace",        "severity": "High",     "name": "Spring Actuator HTTP trace exposed", "stack": "java"},
    {"path": "/actuator/prometheus",       "severity": "Low",      "name": "Spring Actuator Prometheus metrics exposed", "stack": "java"},

    # ── WordPress extra paths ─────────────────────────────────────────────────
    {"path": "/xmlrpc.php",                "severity": "High",     "name": "WordPress XMLRPC enabled (brute-force vector)", "stack": "wordpress"},
    {"path": "/wp-json/wp/v2/users",       "severity": "Medium",   "name": "WordPress REST API user enumeration", "stack": "wordpress"},
    {"path": "/wp-cron.php",               "severity": "Low",      "name": "WordPress cron accessible",         "stack": "wordpress"},
    {"path": "/wp-json/",                  "severity": "Low",      "name": "WordPress REST API root exposed",   "stack": "wordpress"},

    # ── PHP: CGI legacy ───────────────────────────────────────────────────────
    {"path": "/cgi-bin/printenv",          "severity": "Critical", "name": "CGI printenv exposes environment",  "stack": "php"},
    {"path": "/cgi-bin/test-cgi",          "severity": "High",     "name": "CGI test script exposed",           "stack": "php"},

    # ── Go debug endpoints ────────────────────────────────────────────────────
    {"path": "/debug/pprof/",              "severity": "High",     "name": "Go pprof profiling endpoint exposed", "stack": "go"},
    {"path": "/debug/vars",                "severity": "Medium",   "name": "Go expvar endpoint exposed",        "stack": "go"},

    # ── Ruby: additional paths ────────────────────────────────────────────────
    {"path": "/rails/info/properties",     "severity": "Medium",   "name": "Rails info properties exposed",     "stack": "ruby"},
    {"path": "/rails/info/routes",         "severity": "Medium",   "name": "Rails route dump exposed",          "stack": "ruby"},
]

# Content signals to distinguish real files from soft 404s
CONTENT_SIGNALS: dict[str, re.Pattern] = {
    "/.env":                    re.compile(r'^\s*(APP_|DB_|SECRET|KEY|TOKEN|PASSWORD|MAIL_|AWS_)', re.M),
    "/.env.local":              re.compile(r'^\s*(APP_|DB_|SECRET|KEY|TOKEN|PASSWORD)', re.M),
    "/.env.production":         re.compile(r'^\s*(APP_|DB_|SECRET|KEY|TOKEN|PASSWORD)', re.M),
    "/.env.staging":            re.compile(r'^\s*(APP_|DB_|SECRET|KEY|TOKEN|PASSWORD)', re.M),
    "/.env.backup":             re.compile(r'^\s*(APP_|DB_|SECRET|KEY|TOKEN|PASSWORD)', re.M),
    "/.git/config":             re.compile(r'\[core\]'),
    "/.git/HEAD":               re.compile(r'ref: refs/'),
    "/phpinfo.php":             re.compile(r'PHP Version|phpinfo\(\)', re.I),
    "/info.php":                re.compile(r'PHP Version|phpinfo\(\)', re.I),
    "/wp-config.php.bak":       re.compile(r'DB_NAME|DB_PASSWORD', re.I),
    "/wp-config.txt":           re.compile(r'DB_NAME|DB_PASSWORD', re.I),
    "/backup.sql":              re.compile(r'CREATE TABLE|INSERT INTO', re.I),
    "/dump.sql":                re.compile(r'CREATE TABLE|INSERT INTO', re.I),
    "/db.sql":                  re.compile(r'CREATE TABLE|INSERT INTO', re.I),
    "/database.sql":            re.compile(r'CREATE TABLE|INSERT INTO', re.I),
    "/settings.py":             re.compile(r'SECRET_KEY|DATABASES|ALLOWED_HOSTS', re.I),
    "/local_settings.py":       re.compile(r'SECRET_KEY|DATABASES', re.I),
    "/config/database.yml":     re.compile(r'adapter:|database:|password:', re.I),
    "/config/secrets.yml":      re.compile(r'secret_key_base:', re.I),
    "/application.properties":  re.compile(r'spring\.|datasource\.|server\.port', re.I),
    "/application.yml":         re.compile(r'spring:|datasource:|server:', re.I),
    "/web.config":              re.compile(r'<configuration>|connectionStrings', re.I),
    "/appsettings.json":        re.compile(r'"ConnectionStrings"|"Logging"|"AllowedHosts"', re.I),
    "/appsettings.Production.json": re.compile(r'"ConnectionStrings"|"Logging"', re.I),
    "/actuator/env":            re.compile(r'activeProfiles|propertySources', re.I),
    "/terraform.tfvars":        re.compile(r'\w+\s*=\s*"', re.I),
    "/.aws/credentials":        re.compile(r'aws_access_key_id|aws_secret_access_key', re.I),
    "/docker-compose.yml":      re.compile(r'version:|services:', re.I),
    "/docker-compose.yaml":     re.compile(r'version:|services:', re.I),
    "/package.json":            re.compile(r'"name":|"dependencies":', re.I),
    "/.npmrc":                  re.compile(r'registry=|//registry\.npmjs\.org/', re.I),
    "/go.mod":                  re.compile(r'^module\s+', re.M),
    "/Gemfile":                 re.compile(r"source 'https://rubygems\.org'|gem '", re.I),
    "/requirements.txt":        re.compile(r'^\w[\w\-]+(==|>=|<=|~=)', re.M),
    "/pyproject.toml":          re.compile(r'\[project\]|\[tool\.', re.I),
    # PHP tools — must show recognisable HTML or content
    "/phpmyadmin":              re.compile(r'phpMyAdmin|phpmyadmin|pma_', re.I),
    "/pma":                     re.compile(r'phpMyAdmin|phpmyadmin|pma_', re.I),
    "/adminer.php":             re.compile(r'Adminer|adminer', re.I),
    "/test.php":                re.compile(r'<\?php|phpinfo|test', re.I),
    "/debug.php":               re.compile(r'<\?php|debug|var_dump', re.I),
    "/_profiler":               re.compile(r'Symfony|sf-toolbar|profiler', re.I),
    "/__debugbar":              re.compile(r'debugbar|phpdebugbar', re.I),
    "/telescope":               re.compile(r'Laravel Telescope|telescope-api', re.I),
    "/horizon":                 re.compile(r'Laravel Horizon|horizon-api', re.I),
    "/storage/logs/laravel.log":re.compile(r'\[20\d\d-\d\d-\d\d|local\.ERROR|local\.INFO', re.I),
    "/config.php.bak":          re.compile(r'<\?php|\$db_|define\(', re.I),
    # DevOps
    "/Dockerfile":              re.compile(r'^FROM\s+\w|^RUN\s+|^CMD\s+', re.M),
    "/.travis.yml":             re.compile(r'language:|script:|install:', re.I),
    "/Jenkinsfile":             re.compile(r'pipeline\s*\{|stage\s*\(|agent\s+', re.I),
    "/serverless.yml":          re.compile(r'service:|provider:|functions:', re.I),
    "/ansible.cfg":             re.compile(r'\[defaults\]|inventory\s*=|remote_user', re.I),
    "/.github/workflows/deploy.yml": re.compile(r'on:|jobs:|steps:', re.I),
    # Node
    "/next.config.js":          re.compile(r'module\.exports|nextConfig|webpack', re.I),
    "/webpack.config.js":       re.compile(r'module\.exports|entry:|output:', re.I),
    "/nest-cli.json":           re.compile(r'"collection"|"sourceRoot"', re.I),
    "/.nvmrc":                  re.compile(r'^\d+\.\d+', re.M),
    "/yarn.lock":               re.compile(r'^# yarn lockfile|^__metadata:', re.M),
    "/pnpm-lock.yaml":          re.compile(r'lockfileVersion:|packages:', re.I),
    "/node_modules/.package-lock.json": re.compile(r'"lockfileVersion"|"packages"', re.I),
    # Ruby
    "/Gemfile.lock":            re.compile(r'GEM\s*\n\s*remote:|BUNDLED WITH', re.I),
    "/log/production.log":      re.compile(r'Started (GET|POST)|Completed \d{3}', re.I),
    "/log/development.log":     re.compile(r'Started (GET|POST)|Completed \d{3}', re.I),
    "/config/credentials.yml.enc": re.compile(r'.{20,}'),  # any non-empty binary/encrypted content
    # Java
    "/actuator":                re.compile(r'"_links"|"href".*actuator', re.I),
    "/actuator/health":         re.compile(r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"', re.I),
    "/actuator/beans":          re.compile(r'"beans"|"scope"\s*:', re.I),
    "/actuator/logfile":        re.compile(r'\d{4}-\d{2}-\d{2}.*INFO|ERROR|WARN', re.I),
    "/WEB-INF/web.xml":         re.compile(r'<web-app|<servlet', re.I),
    "/META-INF/MANIFEST.MF":    re.compile(r'Manifest-Version:|Main-Class:', re.I),
    # .NET
    "/appsettings.Development.json": re.compile(r'"Logging"|"ConnectionStrings"|"AllowedHosts"', re.I),
    "/elmah.axd":               re.compile(r'ELMAH|Error Log|elmah', re.I),
    "/trace.axd":               re.compile(r'Application Trace|ASP\.NET', re.I),
    # Go
    "/go.sum":                  re.compile(r'^[\w./]+ v[\d.]+', re.M),
    "/config.yaml":             re.compile(r'^\w+\s*:\s*.+', re.M),
    "/config.yml":              re.compile(r'^\w+\s*:\s*.+', re.M),
    # Admin panels — require actual login form or admin UI indicators
    "/admin":                   re.compile(r'login|password|admin|dashboard', re.I),
    "/admin/login":             re.compile(r'login|password|signin|email', re.I),
    "/administrator":           re.compile(r'Joomla|administrator|login', re.I),
    "/wp-admin":                re.compile(r'WordPress|wp-login|dashboard', re.I),
    # Misc universal
    "/graphql":                 re.compile(r'{"data"|{"errors"|graphql|__schema', re.I),
    "/swagger":                 re.compile(r'swagger|openapi|Swagger UI', re.I),
    "/swagger-ui.html":         re.compile(r'swagger|SwaggerUIBundle|openapi', re.I),
    "/api-docs":                re.compile(r'swagger|openapi|"paths"', re.I),
    "/openapi.json":            re.compile(r'"openapi"|"swagger"|"paths"', re.I),
    "/openapi.yaml":            re.compile(r'^openapi:|paths:', re.M),
    "/celeryconfig.py":         re.compile(r'BROKER_URL|CELERY_|broker_url', re.I),
    "/wsgi.py":                 re.compile(r'application\s*=|get_wsgi_application|WSGIHandler', re.I),
    "/manage.py":               re.compile(r'django|execute_from_command_line|os\.environ', re.I),
    "/Pipfile":                 re.compile(r'\[packages\]|\[dev-packages\]|python_version', re.I),
    "/__pycache__/":            re.compile(r'Index of|\.pyc|__pycache__', re.I),
    "/config.py":               re.compile(r'SECRET_KEY|DATABASE_URL|DEBUG\s*=', re.I),
    # Cloud / IaC — must contain actual structured content
    "/terraform.tfstate":       re.compile(r'"terraform_version"|"resources"\s*:', re.I),
    "/terraform.tfstate.backup":re.compile(r'"terraform_version"|"resources"\s*:', re.I),
    "/.kube/config":            re.compile(r'apiVersion:|clusters:|current-context:', re.I),
    "/.aws/config":             re.compile(r'\[profile |region\s*=|output\s*=', re.I),
    "/service-account.json":    re.compile(r'"type"\s*:\s*"service_account"|"private_key"', re.I),
    "/key.json":                re.compile(r'"type"\s*:\s*"service_account"|"client_email"', re.I),
    "/client_secret.json":      re.compile(r'"client_id"|"client_secret"|"installed"|"web"', re.I),
    "/firebase.json":           re.compile(r'"hosting"|"database"|"firestore"|"functions"', re.I),
    "/.circleci/config.yml":    re.compile(r'version:|jobs:|workflows:', re.I),
    "/.gitlab-ci.yml":          re.compile(r'stages:|script:|image:', re.I),
    "/bitbucket-pipelines.yml": re.compile(r'pipelines:|branches:|default:', re.I),
    "/azure-pipelines.yml":     re.compile(r'trigger:|stages:|pool:', re.I),
    # Private keys — PEM header is unmistakable
    "/id_rsa":                  re.compile(r'-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----'),
    "/private.key":             re.compile(r'-----BEGIN (RSA |EC |PRIVATE) KEY-----'),
    "/server.key":              re.compile(r'-----BEGIN (RSA |EC |PRIVATE) KEY-----'),
    "/.netrc":                  re.compile(r'machine\s+\S+\s+login\s+|password\s+\S+'),
    "/.pgpass":                 re.compile(r'^\S+:\d+:\S+:\S+:\S+', re.M),
    "/config/master.key":       re.compile(r'^[a-f0-9]{64}$', re.M),
    # Additional backup formats — binary magic bytes or known SQL content
    "/backup.tar":              re.compile(r'ustar|\.tar', re.I),
    "/backup.tgz":              re.compile(r'\x1f\x8b|\x1F\x8B'),
    "/public_html.zip":         re.compile(r'PK\x03\x04|PK\x05\x06'),
    "/web.zip":                 re.compile(r'PK\x03\x04|PK\x05\x06'),
    "/web.config.bak":          re.compile(r'<configuration>|connectionStrings|<system\.web', re.I),
    # Monitoring UIs — require recognisable login or dashboard text
    "/grafana":                 re.compile(r'Grafana|grafana|<title>Grafana', re.I),
    "/kibana":                  re.compile(r'Kibana|kibana|elastic', re.I),
    "/flower":                  re.compile(r'Flower|celery|flower', re.I),
    "/portainer/":              re.compile(r'Portainer|portainer', re.I),
    "/prometheus/":             re.compile(r'Prometheus|prometheus|/metrics', re.I),
    "/pgadmin/":                re.compile(r'pgAdmin|pgadmin|PostgreSQL', re.I),
    "/mongo-express/":          re.compile(r'mongo-express|MongoDB|mongo_express', re.I),
    "/v1/sys/health":           re.compile(r'"initialized"|"sealed"|"standby"', re.I),
    "/solr/admin/":             re.compile(r'Apache Solr|<title>Solr|solr-config', re.I),
    "/console":                 re.compile(r'JBoss|WildFly|WebLogic|console|management', re.I),
    # Spring Actuator extras
    "/actuator/configprops":    re.compile(r'"configurationProperties"|"prefix"', re.I),
    "/actuator/mappings":       re.compile(r'"dispatcherServlets"|"requestMappingHandlerMapping"', re.I),
    "/actuator/httptrace":      re.compile(r'"traces"|"timestamp"|"request"', re.I),
    "/actuator/prometheus":     re.compile(r'# HELP|# TYPE|jvm_', re.I),
    "/manager/html":            re.compile(r'Tomcat|Apache Tomcat|Manager App', re.I),
    "/host-manager/html":       re.compile(r'Tomcat|Host Manager', re.I),
    # WordPress extras
    "/xmlrpc.php":              re.compile(r'XML-RPC|xmlrpc|faultCode', re.I),
    "/wp-json/wp/v2/users":     re.compile(r'"id"\s*:\s*\d+|"slug"|"name"', re.I),
    "/wp-cron.php":             re.compile(r'<\?php|spawn_cron|wp_cron', re.I),
    "/wp-json/":                re.compile(r'"namespaces"|"authentication"|"wp/v2"', re.I),
    "/wp-config.php~":          re.compile(r'DB_NAME|DB_PASSWORD|table_prefix', re.I),
    # CGI
    "/cgi-bin/printenv":        re.compile(r'SERVER_SOFTWARE|GATEWAY_INTERFACE|PATH_INFO', re.I),
    "/cgi-bin/test-cgi":        re.compile(r'SERVER_SOFTWARE|CGI|GATEWAY_INTERFACE', re.I),
    # Go debug
    "/debug/pprof/":            re.compile(r'goroutine|heap|threadcreate|pprof', re.I),
    "/debug/vars":              re.compile(r'cmdline|memstats|goroutine', re.I),
    # Ruby Rails extras
    "/rails/info/properties":   re.compile(r'Rails version|Ruby version|RubyGems', re.I),
    "/rails/info/routes":       re.compile(r'GET|POST|PATCH|DELETE.*#', re.I),
    "/log/production.log":      re.compile(r'Started (GET|POST)|Completed \d{3}', re.I),
    # API schema docs
    "/graphiql":                re.compile(r'GraphiQL|graphiql|__schema', re.I),
    "/graphql/console":         re.compile(r'GraphQL|graphql|__schema', re.I),
    "/graphql/playground":      re.compile(r'GraphQL Playground|playground|__schema', re.I),
    "/__graphql":               re.compile(r'graphql|__schema|{"data"', re.I),
    "/api/graphql":             re.compile(r'graphql|__schema|{"data"', re.I),
    "/v2/api-docs":             re.compile(r'"swagger"\s*:\s*"2\.|"paths"\s*:', re.I),
    "/v3/api-docs":             re.compile(r'"openapi"\s*:\s*"3\.|"paths"\s*:', re.I),
    # Web server status
    "/server-status":           re.compile(r'Apache Status|Server Version|requests currently being processed', re.I),
    "/server-info":             re.compile(r'Apache Server Information|Module Name', re.I),
    "/nginx_status":            re.compile(r'Active connections:|Reading:|Writing:|Waiting:', re.I),
    "/metrics":                 re.compile(r'# HELP|# TYPE|process_cpu_seconds|go_goroutines', re.I),
    # VCS extras
    "/.git/logs/HEAD":          re.compile(r'\d{10} [+-]\d{4}\s+commit|clone:|checkout:', re.I),
    "/.git/COMMIT_EDITMSG":     re.compile(r'^.{1,500}$', re.M),
    "/.git/packed-refs":        re.compile(r'^[0-9a-f]{40} refs/', re.M),
    "/.git/index":              re.compile(r'^DIRC', re.M),
    "/.gitignore":              re.compile(r'^\*\.|^node_modules|^\.env|^/build', re.M),
    "/.svn/entries":            re.compile(r'^\d+\s*$|svn\+ssh|svn://', re.M),
    "/.hg/store/00manifest.i":  re.compile(r'revlog|manifests|changesets'),
    # Misc
    "/wsdl":                    re.compile(r'<wsdl:|<definitions|<binding', re.I),
    "/crossdomain.xml":         re.compile(r'<cross-domain-policy|<allow-access-from', re.I),
    "/.htpasswd":               re.compile(r'^\w+:\$', re.M),
    "/.htaccess":               re.compile(r'RewriteEngine|Options|AllowOverride|Require', re.I),
    "/robots.txt":              re.compile(r'User-agent:|Disallow:|Allow:', re.I),
    "/sitemap.xml":             re.compile(r'<urlset|<sitemap|<url>', re.I),
    "/error.log":               re.compile(r'\[\w+ \w+ \d+ \d{2}:\d{2}:\d{2}|\[error\]|\[warn\]', re.I),
    "/access.log":              re.compile(r'"GET |"POST |"PUT |"DELETE |\d{3} \d+', re.I),
    "/debug.log":               re.compile(r'ERROR|DEBUG|WARNING|CRITICAL|Traceback', re.I),
    "/app.log":                 re.compile(r'ERROR|DEBUG|INFO|WARNING|\d{4}-\d{2}-\d{2}', re.I),
    "/logs/error.log":          re.compile(r'ERROR|WARN|FATAL|\[\d{4}-\d{2}-\d{2}', re.I),
    "/.DS_Store":               re.compile(r'Bud1|\x00\x00\x00'),
    "/.vscode/settings.json":   re.compile(r'"editor\.|"files\.|"python\.|"workbench\.', re.I),
    "/.idea/workspace.xml":     re.compile(r'<project|<component|<option', re.I),
    "/credentials.json":        re.compile(r'"access_key"|"secret"|"token"|"password"|"type"', re.I),
    "/secrets.json":            re.compile(r'"password"|"secret"|"key"|"token"', re.I),
    "/secrets.yaml":            re.compile(r'password:|secret:|key:|token:', re.I),
    "/secrets.yml":             re.compile(r'password:|secret:|key:|token:', re.I),
    # Low-severity universals — any non-trivial content is a real hit
    "/.env.example":            re.compile(r'^\s*(APP_|DB_|SECRET|KEY|TOKEN|#)', re.M),
    "/backup.zip":              re.compile(r'PK\x03\x04|PK\x05\x06'),
    "/backup.tar.gz":           re.compile(r'\x1f\x8b'),
    "/site.zip":                re.compile(r'PK\x03\x04|PK\x05\x06'),
    "/www.zip":                 re.compile(r'PK\x03\x04|PK\x05\x06'),
    "/package-lock.json":       re.compile(r'"lockfileVersion"|"packages"|"dependencies"', re.I),
    "/CVS/Root":                re.compile(r':pserver:|:ext:|cvs\.', re.I),
}

SEVERITY_SCORE = {"Critical": 30, "High": 20, "Medium": 10, "Low": 5}

REC_BY_STACK = {
    "universal": "Block access to sensitive files via Nginx `deny all` or Apache `Require all denied` directives.",
    "php":       "Remove debug pages and backup files from the PHP web root; use `.htaccess` or Nginx rules.",
    "wordpress": "Delete WordPress config backups; use `deny all` in Nginx or block via `.htaccess`.",
    "python":    "Never place Python source files or config inside the web root; serve only via WSGI.",
    "nodejs":    "Ensure `package.json` and lock files are not served statically; use a CDN or build pipeline.",
    "ruby":      "Move Rails config files above the web root and restrict access via your web server.",
    "java":      "Disable Spring Actuator endpoints in production or restrict with Spring Security.",
    "dotnet":    "Protect `appsettings.json` using Azure Key Vault or environment variable injection.",
    "go":        "Do not serve Go module files or YAML configs from the web root.",
    "devops":    "Never expose CI/CD configs, Dockerfiles, or cloud credentials via HTTP.",
    "cms":       "Restrict CMS admin paths to known IP ranges or behind a VPN.",
}


class ExposureScanner:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "WVS-ExposureScanner/1.0"},
        )

    def _base(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    # Stacks where a content signal is mandatory — a plain 200 is not enough
    _SIGNAL_REQUIRED_STACKS = {"php", "python", "nodejs", "ruby", "java", "dotnet", "go", "devops", "wordpress", "cms"}

    # Paths whose genuine response should never be an HTML document
    _NON_HTML_PATHS = {
        ".env", ".yml", ".yaml", ".json", ".xml", ".sql", ".log",
        ".zip", ".tar", ".gz", ".bak", ".key", ".pem", ".crt",
        ".enc", ".txt", ".ini", ".cfg", ".conf", ".toml", ".lock",
        ".pid", ".dat", ".db", ".sqlite", ".csv",
    }

    def _is_real_hit(self, path: str, entry: dict, resp: httpx.Response) -> bool:
        if resp.status_code != 200:
            return False

        content_type = resp.headers.get("content-type", "").lower()
        is_html_response = "text/html" in content_type

        # If the path extension implies a non-HTML file, reject HTML responses —
        # they are soft-404 pages served by Cloudflare/CDNs/SPAs.
        ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.split("/")[-1] else ""
        if is_html_response and ext in self._NON_HTML_PATHS:
            return False

        text = resp.text[:6000]
        pattern = CONTENT_SIGNALS.get(path)
        if pattern:
            return bool(pattern.search(text))
        # Stack-specific paths with no content signal defined must not be flagged —
        # a generic 200 from Cloudflare/CDN is indistinguishable from a real hit.
        if entry.get("stack") in self._SIGNAL_REQUIRED_STACKS:
            return False
        # Universal/generic paths: reject obvious soft-404 pages
        if len(resp.content) < 20:
            return True
        low = text.lower()
        soft_signals = ["not found", "page not found", "404", "doesn't exist", "no such file"]
        return sum(1 for s in soft_signals if s in low) < 2

    def _extract_emails(self, text: str, limit: int = 20) -> list[str]:
        if not text:
            return []

        emails: list[str] = []
        seen: set[str] = set()
        for match in EMAIL_PATTERN.findall(text):
            normalized = match.strip().strip(".,;:()[]{}<>\"'").lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            emails.append(normalized)
            if len(emails) >= limit:
                break
        return emails

    def scan(self, url: str) -> dict[str, Any]:
        base = self._base(url)
        findings = []
        stacks_hit: set[str] = set()
        discovered_emails: list[str] = []
        seen_emails: set[str] = set()

        for entry in SENSITIVE_PATHS:
            path = entry["path"]
            target = urljoin(base, path)
            try:
                resp = self.client.get(target)
                if self._is_real_hit(path, entry, resp):
                    issue_emails = self._extract_emails(resp.text)
                    for email in issue_emails:
                        if email not in seen_emails:
                            seen_emails.add(email)
                            discovered_emails.append(email)

                    findings.append({
                        "name": entry["name"],
                        "severity": entry["severity"],
                        "path": path,
                        "url": target,
                        "stack": entry.get("stack", "universal"),
                        "status_code": resp.status_code,
                        "content_preview": resp.text[:2000].strip(),
                        "content_length": len(resp.content),
                        "emails": issue_emails,
                    })
                    stacks_hit.add(entry.get("stack", "universal"))
            except Exception:
                continue

        recommendations: list[str] = []
        if findings:
            seen_recs: set[str] = set()
            for stack in stacks_hit:
                rec = REC_BY_STACK.get(stack)
                if rec and rec not in seen_recs:
                    recommendations.append(rec)
                    seen_recs.add(rec)
            if any(f["path"].startswith("/.git") for f in findings):
                recommendations.append("Add `location /.git { deny all; }` to Nginx or `RedirectMatch 404 /\\.git` to Apache.")
            if any(".env" in f["path"] for f in findings):
                recommendations.append("Move .env files above the web root and use environment variable injection instead.")
            if any(f["stack"] == "java" for f in findings):
                recommendations.append("Set `management.endpoints.web.exposure.include=health` only, or add IP allowlist via Spring Security.")

        score = max(0, 100 - sum(SEVERITY_SCORE.get(f["severity"], 5) for f in findings))

        return {
            "status": "issues_found" if findings else "ok",
            "issues": findings,
            "score": score,
            "recommendations": recommendations,
            "discovered_emails": discovered_emails,
        }

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
