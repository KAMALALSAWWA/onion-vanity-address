# onion-vanity-address 🧅

This tool generates Tor Onion Service v3 [vanity address](https://community.torproject.org/onion-services/advanced/vanity-addresses/) with a specified prefix.

Compared to [similar tools](#similar-tools), it uses the [fastest search algorithm](#the-fastest-search-algorithm) 🚀

## Usage

Install the tool locally and run:
```console
$ go install github.com/AlexanderYastrebov/onion-vanity-address@latest

$ onion-vanity-address allium
Found allium... in 12s after 558986486 attempts (48529996 attempts/s)
---
hostname: alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion
hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAAC1ooweCbRP6ncFQs3NRyK40fRwaodrmH572D8py+tCQ==
hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAQEW4Rhot7oroPaETlAEG3GPAntvJ1agF2c7A2AXmBW3WqAH0oUZ1hySvvZl3hc9dSAIc49h1UuCPZacOWp4vQ
```

or use the Docker image:
```console
$ docker pull ghcr.io/alexanderyastrebov/onion-vanity-address:latest
$ docker run  ghcr.io/alexanderyastrebov/onion-vanity-address:latest allium
```

To configure hidden service keypair decode base64-encoded secret key into `hs_ed25519_secret_key` file,
remove `hs_ed25519_public_key` and `hostname` files and restart Tor service:
```console
$ echo PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAQEW4Rhot7oroPaETlAEG3GPAntvJ1agF2c7A2AXmBW3WqAH0oUZ1hySvvZl3hc9dSAIc49h1UuCPZacOWp4vQ | base64 -d > /var/lib/tor/hidden_service/hs_ed25519_secret_key

$ rm /var/lib/tor/hidden_service/hs_ed25519_public_key
$ rm /var/lib/tor/hidden_service/hostname
$ systemctl restart tor

$ cat /var/lib/tor/hidden_service/hostname
alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion
```

## Performance

The tool checks ~45'000'000 keys per second on a laptop:
```console
$ onion-vanity-address --timeout 20s goodluckwiththisprefix
Stopped searching goodluckwiththisprefix... after 20s and 959763220 attempts (47985799 attempts/s)
```

which is ~2x faster than `mkp224o`:
```console
$ timeout 20 docker run ghcr.io/cathugger/mkp224o:master -s -y goodluckwiththisprefix
sorting filters... done.
filters:
        goodluckwiththisprefix
in total, 1 filter
using 8 threads
>calc/sec:18497645.320881, succ/sec:0.000000, rest/sec:79.315507, elapsed:0.100863sec
>calc/sec:18884429.043617, succ/sec:0.000000, rest/sec:0.000000, elapsed:10.108983sec
```

In practice, it finds a 6-character prefix within a minute.
Each additional character increases search time by a factor of 32.

## Similar tools

* [mkp224o](https://github.com/cathugger/mkp224o)
* [oniongen-go](https://github.com/rdkr/oniongen-go)

## The fastest search algorithm

Tor Onion Service [address](https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt) is derived from ed25519 public key.
The tool generates candidate public keys until it finds one that has a specifided prefix when encoded as onion address.

ed25519 keypair consists of:
* 32-byte secret key (scalar) - a random value that serves as the secret
* 32-byte public key (point) - derived by scalar multiplication of the base point by the scalar

ed25519 public key is 32-byte y-coordinate of a point on a [Twisted Edwards curve](https://datatracker.ietf.org/doc/html/rfc8032) equivalent to [Curve25519](https://datatracker.ietf.org/doc/html/rfc7748#section-4.1).

Both `mkp224o` and `onion-vanity-address` leverage additive properties of elliptic curves to avoid full scalar multiplication for each candidate key.
Addition of points requires expesive field inversion operation and both tools utilize batch field inversion (Montgomery trick)
to perform single field inversion per batch of candidate points.

The key performance difference is that while `mkp224o` uses point arithmetic that calculates both coordinates for each candidate point,
`onion-vanity-address` uses curve coordinate symmetry and calculates only y-coordinates to reduce number of field operations.

The algorithm has amortized cost **5M + 2A** per candidate key, where M is field multiplication and A is field addition.

See also:
* [vanity25519](https://github.com/AlexanderYastrebov/vanity25519) — Efficient Curve25519 vanity key generator.
* [wireguard-vanity-key](https://github.com/AlexanderYastrebov/wireguard-vanity-key) — Fast WireGuard vanity key generator.
* [age-vanity-keygen](https://github.com/AlexanderYastrebov/age-vanity-keygen) — Fast vanity age X25519 identity generator.
