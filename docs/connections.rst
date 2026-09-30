Connections, TLS, and authentication
====================================

Basic connection
----------------

Both clients negotiate the transport, S7CommPlus session, protocol version,
and required session setup. Useful state is exposed after connection:

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.168.1.10", port=102)
       print(client.protocol_version)
       print(client.session_id)
       print(client.session_setup_ok)
       print(client.tls_active)
       print(client.protection_level)

If session setup is rejected, ``connect`` raises instead of leaving a
partially usable public client.

Client compatibility
--------------------

The clients share transport, TLS, session-setup, SessionKey, and
response-parsing helpers:

.. list-table:: Authentication support
   :header-rows: 1
   :widths: 42 20 20

   * - Controller/session path
     - ``Client``
     - ``AsyncClient``
   * - V1 without legacy SessionKey attributes
     - Supported
     - Supported
   * - V1 with legacy SessionKey authentication
     - Supported
     - Supported (emulator-tested; not yet validated on hardware)
   * - V2 or V3 with TLS
     - Supported
     - Supported

Both clients authenticate a PLC that advertises legacy public-key fingerprint or
session-challenge attributes. They share the same blob, framing, key-fallback
and renewal logic, and accept the same ``connect()`` options: ``password``,
``allow_legacy_key_fallback``, ``legacy_session_key_refresh_interval`` and
``legacy_s7_1500``. The synchronous path is the one validated on real
controllers; the asyncio path so far runs against the emulator and captured
request layouts only. Password legitimation over a TLS session is also
available through ``authenticate``, and happens during ``connect`` when a
``password`` is given.

Legacy S7-1500 firmware 2.6
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An S7-1512SP on firmware 2.6 has been observed to use different authenticated
fragment digests, symbolic-read qualifiers, and EXPLORE response layouts.
For that non-TLS path, opt in explicitly:

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.0.2.1", use_tls=False, legacy_s7_1500=True)
       tags = client.browse()
       tag = next(tag for tag in tags if tag["name"] == "Example.Value")
       address = [int(part, 16) for part in tag["access_sequence"].split(".")]
       raw = client.read_symbolic(address[0], address[1:])

The setting defaults to ``False`` and is retained across reconnects. It is
incompatible with TLS. It changes browse and symbolic reads after SessionKey
authentication, in both clients; writes, alarms, subscriptions, raw DB access,
other firmware, and the ``AsyncClient`` have not been hardware validated with
this profile.

TLS
---

Controllers requiring encrypted S7CommPlus communication must be connected
with ``use_tls=True``. Provide a CA file in production so the PLC certificate
is verified. Client certificate and key files can also be supplied when the
controller configuration requires mutual authentication:

.. code-block:: python

   client.connect(
       "192.168.1.10",
       use_tls=True,
       tls_ca="certificates/plc-ca.pem",
       tls_cert="certificates/client.pem",
       tls_key="certificates/client-key.pem",
   )

TLS records are carried inside COTP data frames by the library. Wrapping the
TCP socket in a conventional TLS socket is not equivalent and will encrypt the
wrong protocol layer.

Password authentication
-----------------------

The synchronous client accepts the PLC password during connection:

.. code-block:: python

   with Client() as client:
       client.connect(
           "192.168.1.10",
           use_tls=True,
           tls_ca="certificates/plc-ca.pem",
           password="secret",
       )

The asyncio client separates connection from authentication:

.. code-block:: python

   async with AsyncClient() as client:
       await client.connect(
           "192.168.1.10",
           use_tls=True,
           tls_ca="certificates/plc-ca.pem",
       )
       await client.authenticate("secret")

Never log passwords, session keys, challenges, private keys, or decrypted
authentication material.

Troubleshooting
---------------

``Connection refused``
   Confirm routing, TCP port 102, firewall rules, and that the PLC permits the
   configured communication service.

V2 requires TLS
   Reconnect with ``use_tls=True`` and the correct certificates.

Certificate verification fails
   Check that ``tls_ca`` contains the issuer of the PLC certificate and that
   the hostname or address matches the certificate configuration.

Access is refused after connection
   A successful transport session does not guarantee permission to read or
   write every object. Check ``protection_level`` and authenticate if required.

Unexpected disconnect after symbolic access
   Some firmware resets a session after particular symbolic reads. The
   high-level browse path retries once on a fresh connection, but applications
   should still treat disconnects as recoverable failures.
