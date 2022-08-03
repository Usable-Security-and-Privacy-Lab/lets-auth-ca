# Let's Authenticate Certificate Authority

A certificate authority for the Let's Authenticate system. From the paper

[Let’s Authenticate: Automated Certificates for User Authentication](https://www.ndss-symposium.org/ndss-paper/auto-draft-251/),
presented at NDSS 2022.

## Running the CA

```
go run main.go
```

Command line flags include:

- configDir [string] : configuration directory, default 'configs'
- logLevel [integer] : level of logging, default 1
- logPath [string] : path to logging output file, empty string is stdout/stderr,
  default is blank
- signRoot : re-sign the root certificate, default false

Log levels include:

- -1: trace
- 0: debug
- 1: info
- 2: warn
- 3: error
- 4: fatal
- 5: panic

## Configuration file format

Configuration files have the following format:

```yaml
# the name, e.g. "development
- name: [string]
# the database configuration
- database config: [string]

# the display name for the RP
- RP display name: [string]
# the ID for the RP
- RP ID: [string]
# the origin for the RP
- RP origin: [string]

# path to the file containing the public key for this server, in PEM format
- public key: [string]
# path to the file containing the private key for this server, in PEM format
- private key: [string]
# path to the file containing the root certificate for this server, in PEM format
- root certificate: [string]
```

The database configuration string is formatted as:

```
[username]:[password]@tcp([IP]:[port])/[database]?charset=utf8mb4
```

You will need to self-sign a root certificate, as shown below.

## Storing configuration files

Configuration files are stored in the configuration directory with the name
`config.yml`. For example:

- development-config
  - config.yml
- production-config
  - config.yml

## Setting up a development environment

1. Setup the database
1. Create a configuration directory
1. Generate keys and the root certificate
1. Create a configuration file

### Setup the database

1. Install MariaDB.

   ```
   brew install mariadb
   ```

1. Create a MySQL user

   ```mysql
   mysql> CREATE USER 'letsauth'@'localhost' IDENTIFIED BY 'letsauth';
   ```

1. Create the database

   ```mysql
   mysql> CREATE DATABASE lets_auth;
   ```

1. Grant the user privileges to just this new database.

   ```mysql
   mysql> GRANT ALL on lets_auth.* TO 'letsauth'@'localhost';
   ```

### Create a configuration directory

Create a configuration directory in `configs/development`.

### Generate keys and the root certificate

In the configuration directory, run the following:

```
openssl genrsa -out dev-private-key.pem 3072
openssl rsa -in dev-private-key.pem -pubout -out dev-public-key.pem
```

Setup a configuration file, as shown below. Then:

```
go run main.go -root
```

### Create a configuration file

In `configs/development/config.yml`, create a configuration file. Here is a
sample file:

```yaml
name: "development"
database config: "auth:auth@tcp(127.0.0.1:3306)/lets_auth?charset=utf8mb4"

RP display name: "Let's Authenticate"
RP ID: "localhost"
RP origin: "http://localhost:3060"

public key: "dev-public-key.pem"
private key: "dev-private-key.pem"
root certificate: "dev-cert.pem"
```

## Deploying the CA

1. Clone the repository into your home directory on the production server.
1. Run `go build` to build the code. You may need to
   [install Go](https://go.dev/doc/install) first.
1. Set up the database, as above, but with a strong password for the letsauth
   user.
1. Create a production configuration.
1. Create a file in `/etc/systemd/system/letsauthca.go` with the following
   contents:

   ```
   [Unit]
    Description=Let's Authenticate CA
    ConditionPathExists=/home/zappala/lets-auth-ca
    After=network.target
    [Service]
    Type=simple
    User=zappala
    Group=zappala
    WorkingDirectory=/home/zappala/lets-auth-ca
    ExecStart=/home/zappala/lets-auth-ca/lets-auth-ca --configDir lets-auth-ca-prod\
    uction
    Restart=on-failure
    RestartSec=10
    StandardOutput=syslog
    StandardError=syslog
    SyslogIdentifier=letsauthca
    [Install]
    WantedBy=multi-user.target
   ```

1. Setup the daemon:
   ```
   sudo systemctl daemon-reload
   sudo systemctl enable letsauthca
   sudo systemctl start letsauthca
   ```
