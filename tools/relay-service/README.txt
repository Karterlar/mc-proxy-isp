MC Proxy generic relay service source

relay.py implements the relay; manage.py manages a private account store and emits client enrollment files.
mc-proxy-relay.service and install.sh are deployment templates, not a hosted service or an account supplied by this repository.
The existing installation helper assumes an operator-owned health/bootstrap environment; review its preconditions before running it.
No deployment state, server address, customer enrollment, account list or production certificate is included.

For argument details:
  python relay.py --help
  python manage.py --help

Local regression tests:
  python -m unittest test_relay.py

The files in test-fixtures/ are public, self-signed localhost TEST DATA. Never reuse their key or certificate in a deployment.
Prepare your own TLS certificate, private account store, host configuration and access controls for any real service.
