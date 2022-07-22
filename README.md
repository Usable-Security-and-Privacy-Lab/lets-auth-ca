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
- configMode [string] : configuration mode, default 'development'
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

## Database setup

1. Create a MySQL user

```mysql
mysql> CREATE USER 'letsauth'@'localhost' IDENTIFIED BY 'letsauth';
```

2. Create the database

```mysql
mysql> CREATE DATABASE lets_auth;
```

3. Grant the user privileges to just this new database.

```mysql
mysql> GRANT ALL on lets_auth.* TO 'letsauth'@'localhost';
```

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

## Generating keys and the root certificate

```
openssl genrsa -out dev-private-key.pem 3072
openssl rsa -in dev-private-key.pem -pubout -out dev-public-key.pem
```

Setup a configuration file, as shown below. Then:

```
go run main.go -root
```

## Storing configuration files

Configuration files are stored in a subdirectory given by configuration name,
which is passed as the `configMode` flag. The ultimate name of the configuration
file is always `config.yml`. For example:

- configs
  - development
    - config.yml
  - production
    - config.yml

## Sample configuration file

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
