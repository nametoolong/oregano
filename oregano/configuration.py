# Default settings for what is undeclared.
default_settings = {
    "address": "0.0.0.0",
    "server_name_indicator": None,
    "priority_string_as_server": "NORMAL",
    "priority_string_as_client": "NORMAL",
    "verify_server_certs": True,
    "allow_link_cert_mismatch": False,
    "log_server_fingerprint": False,
    "use_length_hiding_with_server": False,
    "use_length_hiding_with_client": False,
    "padding_range_with_server": (0, 0),
    "padding_range_with_client": (0, 0),
    "suppress_exceptions": False
}

import oregano.handler

class EvilHandler(oregano.handler.DefaultHandler):

    '''
    You can rewrite these methods:

    __init__(self, link)
    # a new instance is created for every connection
    # if you override __init__
    # always remember to invoke oregano.handler.DefaultHandler.__init__(self, link)

    forward_cell_received(self, cell) # note that this method calls the methods below
    on_forward_padding_cell(self, circid, cell_content)
    on_forward_create_cell(self, circid, cell_content)
    on_forward_relay_cell(self, circid, cell_content)
    on_forward_destory_cell(self, circid, cell_content)
    on_forward_create_fast_cell(self, circid, cell_content)
    on_forward_relay_early_cell(self, circid, cell_content)
    on_forward_create2_cell(self, circid, cell_content)
    on_forward_padding_negotiate_cell(self, circid, cell_content)
    on_forward_vpadding_cell(self, circid, cell_content)
    on_forward_unknown_cell(self, circid, cell_content)

    backward_cell_received(self, cell) # note that this method calls the methods below
    on_backward_padding_cell(self, circid, cell_content)
    on_backward_created_cell(self, circid, cell_content)
    on_backward_relay_cell(self, circid, cell_content)
    on_backward_destory_cell(self, circid, cell_content)
    on_backward_created_fast_cell(self, circid, cell_content)
    on_backward_relay_early_cell(self, circid, cell_content)
    on_backward_created2_cell(self, circid, cell_content)
    on_backward_vpadding_cell(self, circid, cell_content)
    on_backward_unknown_cell(self, circid, cell_content)


    Use self.send_to_remote(data) to send to the server and self.send_to_session(data) to send to the client.
    Use methods of self.server_or_conn or self.client_or_conn respectively (see ORConnImpl in onion.py) to make cells.
    '''

    def on_forward_create2_cell(self, circid, cell_content):
        super(EvilHandler, self).on_forward_create2_cell(circid, cell_content)

        # example:
        # send an extra VPADDING cell after each CREATE2 cell to mark it as our connection
        self.send_to_remote(self.server_or_conn.vpadding_cell('EVIL    EVIL        LIVE    LIVE'))

import random

class PIPIResistanceHandler(oregano.handler.DefaultHandler):

    '''
    This handler tries to fool Port Independent Protocol Identification,
    which is used by some ISPs to detect Tor traffic
    '''

    def on_forward_create_fast_cell(self, circid, cell_content):
        super(PIPIResistanceHandler, self).on_forward_create_fast_cell(circid, cell_content)
        self.send_to_remote(self.server_or_conn.vpadding_cell('\x00' * random.randint(1200, 2000)))

    def on_forward_relay_early_cell(self, circid, cell_content):
        super(PIPIResistanceHandler, self).on_forward_relay_early_cell(circid, cell_content)
        self.send_to_remote(self.server_or_conn.vpadding_cell('\x00' * random.randint(1200, 2000)))

    def on_forward_create2_cell(self, circid, cell_content):
        super(PIPIResistanceHandler, self).on_forward_create2_cell(circid, cell_content)
        self.send_to_remote(self.server_or_conn.vpadding_cell('\x00' * random.randint(1200, 2000)))

# The main configuration.
# Each key-value pair declares a proxy instance.
settings = {
    # the key should be the server address (currently ignored) and the value must be a dictionary
    ("127.0.0.1", 39956): {
        # our OR nickname, as in torrc
        "nickname": "oregano",

        # our OR address, as in torrc
        "address": "0.0.0.0",

        # our announced average and burst bandwidth in bytes
        "announced_bandwidth": (10485760, 671088640),

        # the address we should forward connections to
        "server_address": ("127.0.0.1", 39956),

        # the address we should be listening at
        "listen_address": ("0.0.0.0", 40056),

        # our certificate, must be in DER format
        "cert": "certs/cert.crt",

        # the 1024-bit RSA key corresponding to our certificate, must be in PEM format
        "key": "certs/key.key",

        # our 1024-bit RSA onion key, must be in PEM format
        "onion_secret_key": "certs/onion.key",

        # base64 encode of our ntor onion key, the private part
        "ntor_onion_secret_key": "MAnGt1ArmYV1/W8AwfVlyxIQXV+NIMRttytfD2+J1F4=",

        # the link protocol versions we are offering to the upstream server
        # see https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n571 for available values
        "versions_offered_to_server": (3, 4, 5),

        # the link protocol versions we are offering to our clients
        # see https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n571 for available values
        "versions_offered_to_client": (3, 4, 5),

        # the SNI to be sent to the upstream server
        # for example
        # "server_name_indicator": "example.org",
        "server_name_indicator": None,

        # the GnuTLS priority string as a TLS server (when talking to our clients)
        "priority_string_as_server": "NORMAL",

        # the GnuTLS priority string as a TLS client (when talking to the upstream server)
        "priority_string_as_client": '''
NONE:
+VERS-TLS1.2:
+VERS-TLS1.1:
+VERS-TLS1.0:
+AES-128-CBC:
+AES-256-CBC:
+SHA256:
+SHA1:
+RSA:
+ECDHE-RSA:
+ECDHE-ECDSA:
+DHE-DSS:
+SIGN-RSA-SHA256:
+SIGN-RSA-SHA384:
+SIGN-RSA-SHA1:
+SIGN-ECDSA-SHA256:
+SIGN-ECDSA-SHA384:
+SIGN-ECDSA-SHA1:
+SIGN-DSA-SHA1:
+GROUP-SECP256R1:
+GROUP-SECP384R1:
+CTYPE-X509:
%NO_TICKETS:
%SAFE_RENEGOTIATION:
%NO_ETM:
%LATEST_RECORD_VERSION
'''.replace('\n', '').strip(),

        # whether to verify the server's CERTS
        "verify_server_certs": True,

        # whether to allow actual TLS link certificate to differ from that in CERTS cell
        "allow_link_cert_mismatch": False,

        # the server's OR fingerprint
        # set to None to disable verification
        # for example
        # "server_fingerprint": "565036B6C1509391E2D6C84F02D76A4BFE4CFE8A",
        "server_fingerprint": None,

        # whether to log the server's OR fingerprint every connection
        # can be annoying but is useful when debugging
        "log_server_fingerprint": False,

        # whether to use length hiding when talking to the upstream server
        "use_length_hiding_with_server": True,

        # whether to use length hiding when talking to our clients
        "use_length_hiding_with_client": False,

        # the range of padding when talking to the upstream server, if use_length_hiding_with_server is True
        # the first element of the tuple must be negative or zero
        # the second element must be positive or zero
        "padding_range_with_server": (-64, 512),

        # the range of padding when talking to our clients, if use_length_hiding_with_client is True
        "padding_range_with_client": (0, 0),

        # your handler to do evil things
        # comment out this line to disable
        "handler": EvilHandler,

        # the TLS credentials we use when talking to the upstream server
        # setting this will enforce server certificate verification using those credentials
        # don't forget to import X509Credentials and other classes before the settings dict
        # comment out to disable
        # for example
        # "client_tls_credentials": X509Credentials(trusted=[X509Certificate(open("certs/ca.crt").read())]),
        "client_tls_credentials": None,

        # whether to suppress exceptions during processing of request
        # note that those exceptions are really annoying
        "suppress_exceptions": True

        # in case you needed to use a proxy
        # "proxy": ("HTTP", "127.0.0.1", 1080)
        # "proxy": ("SOCKS4", "127.0.0.1", 1080)
        # "proxy": ("SOCKS5", "127.0.0.1", 1080)
    }
}
