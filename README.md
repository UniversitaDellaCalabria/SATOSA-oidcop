SATOSA oidcop frontend
----------------------

SATOSA Frontend based on idetity python oidcop.


## Features

Endpoints:
* [x] provider discovery
* [x] jwks uri
* [x] authorization
* [x] token
* [x] userinfo
* [x] registration
* [x] registration_read endpoint
* [x] introspection endpoint (https://github.com/IdentityPython/SATOSA/pull/378/commits/473310fb5968561f962bf6bcc6b6eacbf78f0b3e)
* [ ] token exchange

## Requirements

- satosa
- mongodb, see [Satosa-Saml2Spid mongo example](https://github.com/italia/Satosa-Saml2Spid/tree/oidcop/mongo).


## Setup

````
pip install satosa_oidcop
````

## Demo

[Satosa-Saml2Spid](https://github.com/italia/Satosa-Saml2Spid/) is a custom Satosa configuration to deal with many SAML2 and OIDC Relying parties and many eduGain and SPID Identity Provider.

![satosa_oidcop](images/dive.gif)

## Contributions

Feel free to open issues and pull requests, we build communities!

## Roadmap

* [x] unit tests
* [x] pytest mongo mock
* [x] test response_type = "code id_token token" (https://github.com/IdentityPython/SATOSA/pull/378/commits/a61dc99503bcb9d4982b77a6ddcf0c41b6732915)
* [x] auto prune expired sessions with mongodb index (https://github.com/IdentityPython/SATOSA/pull/378/commits/137993f77bfb05b44f25ba6df3784e8fb86a31ce, [mongo index](https://github.com/italia/Satosa-Saml2Spid/tree/oidcop/mongo#create-expired-session-deletion))
* [x] token refresh (https://github.com/IdentityPython/SATOSA/pull/378/commits/59c0a53fa73e70551d76c5355c051a7389ab99fd)
* [ ] ~rfc7523 - private_key_jwt test~ > a RP cannot reach the token endpoint if a user have not passed by authz endpoint before. private_key_jwt is a kind of authentication where the user interaction is not needed.
* [ ] DPoP support

## Tests

Before you run the tests mind that you've to start a local mongod instance.

````
pip install pytest
pytest tests/
````

## Authors

- Giuseppe De Marco <at> Università della Calabria

## Credits

- Roland Hedberg
- Andrea Ranaldi <at> ISTRA Ambiente
- Identity Python Community
