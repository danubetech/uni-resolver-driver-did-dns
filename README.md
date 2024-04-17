![DIF Logo](https://raw.githubusercontent.com/decentralized-identity/universal-resolver/master/docs/logo-dif.png)

# Universal Resolver Driver: did:dns

This is a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver/) driver for **did:dns** identifiers.

## Specifications

* [Decentralized Identifiers](https://www.w3.org/TR/did-core/)
* [DID Method Specification](https://danubetech.github.io/did-method-dns/)

## Example DIDs

```
did:dns:danubetech.com
```

## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t universalresolver/driver-did-dns
docker run -p 8080:8080 universalresolver/driver-did-dns
curl -X GET http://localhost:8080/1.0/identifiers/did:dns:danubetech.com
```

## Build (native Java)

Maven build:

    mvn clean install

## Driver Environment Variables

The driver recognizes the following environment variables:

### `uniresolver_driver_did_dns_dnsServers`

 * Specifies a list of DNS servers to use.
 * Default value: (empty string)

### `uniresolver_driver_did_dns_didKeyResolver`

 * Specifies the URL of a did:key resolver.
 * Default value: `https://dev.uniresolver.io/1.0/`
