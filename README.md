# s4pg

s4pg stands for "shamir's secret sharing scheme privacy guard". While there
exist other CLI tools that perform SSSS in some capacity, s4pg was designed
to be just as simple but ultimately more comprehensive than these tools. With only 
two subcommands and minimal flags, s4pg provides the following features:

* An initial layer of protection using a user-provided password, PBKDF2 and ChaCha20-Poly1305
* A secondary layer of protection using a randomly generated secret key and ChaCha20-Poly1305
* Shamir's secret sharing scheme to split the secret key with duplication of the ciphertext across all shares

All cryptographic primitives are handled through either 
[hashicorp/vault](https://pkg.go.dev/github.com/hashicorp/vault) 
or [golang/crypto](https://pkg.go.dev/golang.org/x/crypto). That being said, please vet this
source code before using in a high-risk situation.

## Setup

You can install s4pg locally using `go get`. Make sure you are using go version 1.13+.

```
GO111MODULE=on go get -v github.com/dmhacker/s4pg/cmd/s4pg@latest
```

You can also update s4pg using the same command.

## Usage

s4pg follows the same general format as ssss. It has two subcommands, `split` and `combine`.

The `split` command takes as input a file, a count and a threshold. It will produce
${count} shares, of which at least ${threshold} are required to recreate the original file.

The `combine` command operates in reverse. It takes as input several files, each of which
is assumed to be a valid share, produced by `split`ing a file. The original file will be
recreated in the user's current directory if the user is able to meet the ${threshold} criteria.

You can find out more details with the following command.

```
s4pg -h
```

## Testing

To run all tests, use the following command.

```
go test ./... -v
```
