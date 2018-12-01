from oregano.onion import *

class DefaultHandler(object):
    __slots__ = ('link', )

    def __init__(self, link):
        self.link = link

    def __getattr__(self, name):
        return getattr(self.link, name)

    def process_forward_relay_cell(self, circid, cell_content):
        result = self.circ_manager.relay_forward(circid, cell_content)

        if result[0] == FINISHED:
            response_for_client, response_for_server, = result[1:]

            if response_for_client:
                self.send_to_session(response_for_client)

            if response_for_server:
                self.send_to_remote(response_for_server)

        elif result[0] == INJECTED:
            with self.circ_manager.lock:
                streamid, circid, circid_server, = result[1:]

                response_for_client, response_for_server = self.circ_manager.create_descriptor_response(
                    self.server.dir_identity_response, circid, circid_server, streamid)

                for response in response_for_client:
                    self.send_to_session(response)

                for response in response_for_server:
                    self.send_to_remote(response)

    def process_backward_relay_cell(self, circid, cell_content):
        response_for_server, response_for_client = self.circ_manager.relay_backward(circid, cell_content)

        if response_for_server:
            self.send_to_remote(response_for_server)

        if response_for_client:
            self.send_to_session(response_for_client)

    def forward_cell_received(self, cell):
        circid, cell_content = self.client_or_conn.decode_circid(cell)
        command = cell_content[0]

        if command == COMMAND_RELAY:
            self.on_forward_relay_cell(circid, cell_content)
        elif command == COMMAND_RELAY_EARLY:
            self.on_forward_relay_early_cell(circid, cell_content)
        elif command == COMMAND_DESTROY:
            self.on_forward_destory_cell(circid, cell_content)
        elif command == COMMAND_PADDING:
            self.on_forward_padding_cell(circid, cell_content)
        elif command == COMMAND_VPADDING:
            self.on_forward_vpadding_cell(circid, cell_content)
        elif command == COMMAND_CREATE_FAST:
            self.on_forward_create_fast_cell(circid, cell_content)
        elif command == COMMAND_CREATE:
            self.on_forward_create_cell(circid, cell_content)
        elif command == COMMAND_CREATE2:
            self.on_forward_create2_cell(circid, cell_content)
        elif command == COMMAND_PADDING_NEGOTIATE:
            self.on_forward_padding_negotiate_cell(circid, cell_content)
        else:
            self.on_forward_unknown_cell(circid, cell_content)

    def on_forward_padding_cell(self, circid, cell_content):
        self.send_to_remote(self.server_or_conn.add_circid(0, cell_content))

    def on_forward_create_cell(self, circid, cell_content):
        payload = cell_content[1:]

        response_for_client, response_for_server = self.circ_manager.create(circid, payload, self.server.onion_privkey)
        
        if response_for_client:
            self.send_to_session(response_for_client)

        if response_for_server:
            self.send_to_remote(response_for_server)

    def on_forward_relay_cell(self, *args):
        self.process_forward_relay_cell(*args)

    def on_forward_destory_cell(self, circid, cell_content):
        circid_server = self.circ_manager.destroy(circid)

        if circid_server:
            self.send_to_remote(self.server_or_conn.add_circid(circid_server, cell_content))

    def on_forward_create_fast_cell(self, circid, cell_content):
        payload = cell_content[1:]

        response, circid_server = self.circ_manager.create_fast(circid, payload)

        if response:
            self.send_to_session(response)

        if circid_server:
            self.send_to_remote(self.server_or_conn.add_circid(circid_server, cell_content))

    def on_forward_relay_early_cell(self, *args):
        self.process_forward_relay_cell(*args)

    def on_forward_create2_cell(self, circid, cell_content):
        payload = cell_content[1:]

        response_for_client, response_for_server = self.circ_manager.create2(circid, payload, self.server.ntor_onion_key)

        if response_for_client:
            self.send_to_session(response_for_client)

        if response_for_server:
            self.send_to_remote(response_for_server)

    def on_forward_padding_negotiate_cell(self, circid, cell_content):
        if self.server_or_conn.version >= 5:
            self.send_to_remote(self.server_or_conn.add_circid(0, cell_content))

    def on_forward_vpadding_cell(self, circid, cell_content):
        self.send_to_remote(self.server_or_conn.add_circid(0, cell_content))

    def on_forward_unknown_cell(self, circid, cell_content):
        import logging
        logging.info('Received an unexpected forward cell: {}'.format(cell_content[0].encode('hex')))

    def backward_cell_received(self, cell):
        circid, cell_content = self.server_or_conn.decode_circid(cell)

        command = cell_content[0]

        if command == COMMAND_RELAY:
            self.on_backward_relay_cell(circid, cell_content)
        elif command == COMMAND_RELAY_EARLY:
            self.on_backward_relay_early_cell(circid, cell_content)
        elif command == COMMAND_DESTROY:
            self.on_backward_destory_cell(circid, cell_content)
        elif command == COMMAND_PADDING:
            self.on_backward_padding_cell(circid, cell_content)
        elif command == COMMAND_VPADDING:
            self.on_backward_vpadding_cell(circid, cell_content)
        elif command == COMMAND_CREATED_FAST:
            self.on_backward_created_fast_cell(circid, cell_content)
        elif command == COMMAND_CREATED:
            self.on_backward_created_cell(circid, cell_content)
        elif command == COMMAND_CREATED2:
            self.on_backward_created2_cell(circid, cell_content)
        else:
            self.on_backward_unknown_cell(circid, cell_content)

    def on_backward_padding_cell(self, circid, cell_content):
        self.send_to_session(self.client_or_conn.add_circid(0, cell_content))

    def on_backward_created_cell(self, circid, cell_content):
        pass

    def on_backward_relay_cell(self, *args):
        self.process_backward_relay_cell(*args)

    def on_backward_destory_cell(self, circid, cell_content):
        circid_client = self.circ_manager.destroy_from_server(circid)

        if circid_client:
            self.send_to_session(self.client_or_conn.add_circid(circid_client, cell_content))

    def on_backward_created_fast_cell(self, circid, cell_content):
        payload = cell_content[1:]

        response_for_server, response_for_client = self.circ_manager.created_fast(circid, payload)

        if response_for_server:
            self.send_to_remote(response_for_server)

        if response_for_client:
            self.send_to_session(response_for_client)

    def on_backward_relay_early_cell(self, *args):
        self.process_backward_relay_cell(*args)

    def on_backward_created2_cell(self, circid, cell_content):
        pass

    def on_backward_vpadding_cell(self, circid, cell_content):
        self.send_to_session(self.client_or_conn.add_circid(0, cell_content))

    def on_backward_unknown_cell(self, circid, cell_content):
        import logging
        logging.info('Received an unexpected backward cell: {}'.format(cell_content[0].encode('hex')))
