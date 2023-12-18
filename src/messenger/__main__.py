from . import Client, ClientState


def menu() -> ClientState:

    def print_menu() -> None:
        print('Select option: ')
        print('0 - Passive mode: ')
        print('1 - Active mode: ')
        print('2 - Exit: ')
        print()

    print_menu()
    option: str = None
    while not option in {'0', '1', '2'}:
        option: str = input('Introduce option: ')
    if option == '0':
        return ClientState.PASSIVE
    elif option == '1':
        return ClientState.ACTIVE
    else:
        exit(0)


def ask_user_name() -> str:
    return input('Introduce your username: ')


def ask_peer_name() -> str:
    return input('Introduce your peer\'s username: ')

def main():

    # Initialization
    user_name: str = ask_user_name()

    # Menu options
    client_mode = menu()
    client = Client(user_name, client_mode)

    if client_mode == ClientState.ACTIVE:
        peer_name: str = ask_peer_name()
        client.send_public_key(peer_name)
        client.wait_for_public_key()
    elif client_mode == ClientState.PASSIVE:
        client.wait_for_public_key()

    if client.state == ClientState.CONNECTED:
        client.wait_for_messages()

        while True:
            input_text = input()
            if input_text != '':
                client.send_message(input_text)


if __name__ == "__main__":
    try:
        while True:
            main()
    except KeyboardInterrupt:
        print()
        print('Exiting...')
