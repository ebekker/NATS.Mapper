
# NATS.Mapper

Solution for authenticating and mapping external credentials to NATS NKeys.

-----

## Overview

The NATS Mapper is a service and client combination that allows you to resolve an identity
using an external authentication service, and then map that identity to an NKey pair for
subsequent authentication to a NATS server.

The NAT Mapper Server can be configured to map a number of identities under various identity
systems to an NKeys pairs.  The server will resolve the identity to return the NKeys JWT
(public) component.  Then it can be used to sign a challenge nonce (as issued by the
NATS server) using the NKeys Seed (private) component.

Accordingly the NATS Mapper Client can be used to resolve the identity of the calling
client using an external Identity System and then authenticate itself to the NATS Mapper
Server to resolve a mapped JWT and subsequently, a signed challenge nonce.
The NATS Mapper Client can be used to integrate with the official NATS .NET Client in
order to support the cross-system interaction transparently.

## Supported External Identity Systems

Currently the following External Identity Systems are supported.

### Kerberos

Kerberos-based authentication is used to resolve the identity running the client.
The fully qualified Kerberos name of the user is then mapped to an NKeys pair, such
as `john.doe@domain.local`.

Currently, the user credentials must be provided explicitly to the client, but a
future enhancement is planned to resolve the credentials from the running context
such as from a _keytab_ file.

### AWS IAM 

AWS IAM credentials can be used to resolve the identity of the running client.  The
credentials can be provided explicitly or can be resolved from the running context
using a pre-defined set of fallback locations as defined by the AWS SDK.

The resolved IAM arn can then be used to map to an NKeys pair, such as
`arn:aws:iam::123456789012:user/john_doe`.

Additionally, you can specify a wild-card pattern to map a group of identities
to a single NKeys pair.  For example `arn:aws:iam::123456789012:*` would map _all_
identities (users, roles, EC2 instances, Lambdas, etc.) under a single root account
to a single NKeys pair. Or `arn:aws:iam::123456789012:user/*` would map all
_user_ identities.

-----

TODO: more details and samples
