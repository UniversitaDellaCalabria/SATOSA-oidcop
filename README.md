SATOSA oidcop frontend
----------------------

![CI build](https://github.com/UniversitaDellaCalabria/satosa-oidcop/workflows/satosa_oidcop/badge.svg)
![Python version](https://img.shields.io/badge/license-Affero%203-blue.svg)
[![Downloads](https://pepy.tech/badge/satosa-oidcop)](https://pepy.tech/project/satosa-oidcop)
[![Downloads per week](https://pepy.tech/badge/satosa-oidcop/week)](https://pepy.tech/project/satosa-oidcop)
![License](https://img.shields.io/badge/python-3.7%20%7C%203.8%20%7C%203.9-blue.svg)


SATOSA Frontend based on [identity python oidcop](https://github.com/IdentityPython/oidc-op).


## Features

Endpoints:
* [x] provider discovery
* [x] jwks uri
* [x] authorization
* [x] token
* [x] userinfo
* [x] registration
* [x] registration_read endpoint
* [x] introspection endpoint
* [ ] token exchange

## Requirements

- satosa
- mongodb, see [Satosa-Saml2Spid mongo example](https://github.com/italia/Satosa-Saml2Spid/tree/master/mongo).


## Setup

````
pip install satosa_oidcop
````

## Configuration

Anyone can migrate its oidcop configuration, from flask_op or django-oidc-op or whatever, in SATOSA and without any particular efforts. Looking at the [example configuration](example/oidcop_frontend.yaml) we see that `config.op.server_info` have a standard SATOSA configuration with the only addition of the following customizations, needed in SATOSA for interoperational needs. These are:

- autentication
````
        authentication:
          user:
            acr: urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword
            class: satosa.frontends.oidcop.user_authn.SatosaAuthnMethod
````

 - userinfo
 ````
        userinfo:
          class: satosa.frontends.oidcop.user_info.SatosaOidcUserInfo
````

**authentication** inherits `oidcop.user_authn.user.UserAuthnMethod` and overloads two methods involved in user authentication and verification. These tasks are handled by SATOSA in its authentication backends.

**userinfo** inherits `oidcop.user_info.UserInfo` and proposes a way to store the claims of the users when they comes from the backend. The claims are stored in the session database (actually mongodb) and then they will be fetched during userinfo endpoint (and also token endpoint, for having  them optionally in id_token claims).


#### SSO and cookies

oidcop SSO and cookies were not have been implemented because SATOSA doesn't support logout, because of this they are quite useless at this moment.

#### Client and Session Storage

MongoDB is the storage, [here](https://github.com/italia/Satosa-Saml2Spid/tree/oidcop/mongo) some brief descriptions for a demo setup. The interface to SATOSA oidcop storage is `satosa.frontends.oidcop.storage.base.SatosaOidcStorage` and it have three methods:

- **get_client_by_id**(self, client_id:str, expired:bool = True)
- **store_session_to_db**(self, session_manager, **kwargs)
- **load_session_from_db**(self, req_args, http_headers, session_manager, **kwargs)

`satosa.frontends.oidcop.storage.mongo.Mongodb` overloads them to have I/O operations on mongodb.


## Demo

[Satosa-Saml2Spid](https://github.com/italia/Satosa-Saml2Spid/) is a custom Satosa configuration to deal with many SAML2 and OIDC Relying parties and many eduGain and SPID Identity Provider.

![satosa_oidcop](images/dive.gif)

## Contributions

Feel free to open issues and pull requests, we build communities!

## Developer notes

#### Storage design
At this time the storage logic is based on oidcop session_manager load/dump/flush methods.
Each time a request is handled by an endpoint the oidcop session manager loads the definition from the storage, **only which one are strictly related to the request will be loaded** in the in memory storage of oidcop.


#### Roadmap

* [x] unit tests
* [x] pytest mongo mock
* [x] test response_type = "code id_token token" (https://github.com/IdentityPython/SATOSA/pull/378/commits/a61dc99503bcb9d4982b77a6ddcf0c41b6732915)
* [x] auto prune expired sessions with mongodb index (https://github.com/IdentityPython/SATOSA/pull/378/commits/137993f77bfb05b44f25ba6df3784e8fb86a31ce, [mongo index](https://github.com/italia/Satosa-Saml2Spid/tree/oidcop/mongo#create-expired-session-deletion))
* [x] token refresh (https://github.com/IdentityPython/SATOSA/pull/378/commits/59c0a53fa73e70551d76c5355c051a7389ab99fd)
* [ ] DPoP support

#### Tests

Before you run the tests mind that you've to start a local mongod instance.

````
pip install pytest
pytest --cov=satosa_oidcop -v --cov-report term --cov-fail-under=95 tests/
````

## Authors

- Giuseppe De Marco <at> Università della Calabria

## Credits

- Roland Hedberg
- Andrea Ranaldi <at> ISPRA Ambiente
- Identity Python Community
