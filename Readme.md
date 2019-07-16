bcryptbuddy
==========

bcryptbuddy is a cli tool to generate and verify bcrypt hashes

## Building

Using go 1.12 or greater you can build via:

`go build`

Or install into $GOPATH/bin via:

`go get -u github.com/psanford/bcryptbuddy`

## Usage

To hash a password:

```
$ ./bcryptbuddy hash
Password: hello
$2a$10$lVnFYgfa3R5B4t.NqmUY.u.haTqYhtsRuhFIuT.itt7bc/GrRAdy2
```

To verify a password matches a hash:

```
$ ./bcryptbuddy verify
Bcrypt Hash: $2a$10$lVnFYgfa3R5B4t.NqmUY.u.haTqYhtsRuhFIuT.itt7bc/GrRAdy2
Password: hello
ok
```
