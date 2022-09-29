import server

PORT_FILE = "port.info"


def getPort(filename):
    defaultPort = 1234
    try:
        file = open(filename)
        port = int(file.readline().strip())
        file.close()
        return port
    except Exception as e:
        print(f"Failed to read port from {filename}: {e}\nUsing default port {defaultPort}.")
        return defaultPort


if __name__ == "__main__":
    port = getPort(PORT_FILE)
    srv = server.Server(port)
    if not srv.start():
        print("Server couldn't start")
        exit(-1)