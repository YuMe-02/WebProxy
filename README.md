

# WebProxy

WebProxy is a C-based application designed to act as an intermediary for requests from clients seeking resources from other servers.

## Features

- **Request Forwarding**: Forwards client requests to the appropriate server.
- **Response Handling**: Receives server responses and relays them back to the client.
- **Logging**: Maintains logs of client requests and server responses.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/YuMe-02/WebProxy.git
   ```

2. Navigate to the project directory:

   ```bash
   cd WebProxy
   ```

3. Compile the source code using `make`:

   ```bash
   make
   ```

## Usage

After successful compilation, run the proxy server with the following command:

```bash
./bin/webproxy [port]
```

Replace `[port]` with the desired port number on which the proxy should listen.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your changes.
