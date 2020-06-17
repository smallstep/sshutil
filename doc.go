/*
Package sshutil provides utilities for working with the ssh protocol at the
application layer. SSH is specified by: https://tools.ietf.org/html/rfc4251.

The ssh server API functions similar to 'net/http'. Register handlers for
various parts of the protocol and process each session as new client
connections arrive.
*/
package sshutil
