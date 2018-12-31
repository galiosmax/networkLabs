import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;

import org.xbill.DNS.*;

public class Socks {

    private final static int BUFFER_SIZE = 8192;

    private final static int VERSION = 0x05;
    private final static int COMMANDS = 0x01;
    private final static int COMMAND = 0x00;
    private final static int TCPIP = 0x01;
    private final static int RESERVED = 0x00;
    private final static int IPV4 = 0x01;
    private final static int DNS = 0x03;
    private final static int SIZEGREETINGS = 2;
    private final static int SIZECONNECTION = 10;
    private final static int SIZEIP = 4;
    private final static int OK = 0x00;
    private final static int ERROR = 0x01;

    private int serverPort;
    private Selector selector;
    private ServerSocketChannel serverSocketChannel;
    private DatagramChannel dnsChannel;
    private boolean isRunning;
    private HashMap<SocketChannel, Client> clients = new HashMap<>();
    private HashMap<SocketChannel, Client> remotes = new HashMap<>();
    private HashMap<Integer, Client> dns = new HashMap<>();

    public static void main(String[] args) {

        Socks server;
        try {
            server = new Socks(args);
            server.start();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    class Client {

        SocketChannel client, remote;
        boolean connected = false;
        boolean registred = false;
        //boolean gotRegister = false;
        //boolean gotConnection = false;
        //boolean forwarded = true;
        InetAddress address = null;
        int port = 0;
        //byte[] greetingsBuffer, connectionBuffer, clientBuffer, remoteBuffer;

        Client(SocketChannel channel) throws IOException {
            this.client = channel;
            client.configureBlocking(false);
            //greetingsBuffer = new byte[SIZEGREETINGS];
            //connectionBuffer = new byte[SIZECONNECTION];
        }

        void newRemoteData() throws IOException {

            ByteBuffer byteBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            if (remote.isConnected()/* && forwarded*/) {
                int bytes = remote.read(byteBuffer);
                if (bytes > 0) {
                    //clientBuffer = ByteBuffer.wrap(byteBuffer.array(), 0, bytes).array();
                    //forwarded = false;
                    //writeClient();
                    bytes = client.write(ByteBuffer.wrap(byteBuffer.array(), 0, bytes));
                    System.out.println("Forwarded " + bytes + " bytes to client");
                }
                else if (bytes == -1) {
                    System.out.println("Removing " + client.getRemoteAddress());

                    client.close();
                    remote.close();
                }
            }
            byteBuffer.clear();
        }

        void newClientData() throws IOException {
            ByteBuffer byteBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            int bytes = -1;
            if (client.isConnected())
                bytes = client.read(byteBuffer);
            byteBuffer.flip();

            if (!registred) {
                if (bytes > 0) {

                    int version = byteBuffer.get();
                    if (version != VERSION) {
                        throw new IOException("WRONG VERSION: " + version);
                    }

                    int commands = byteBuffer.get();
                    if (commands != COMMANDS) {
                        throw new IOException("WRONG NUMBER OF COMMANDS: " + commands);
                    }

                    int command = byteBuffer.get();
                    if (command != COMMAND) {
                        throw new IOException("WRONG COMMAND: " + command);
                    }

                    ByteBuffer greetingsBuffer = ByteBuffer.allocate(SIZEGREETINGS);
                    greetingsBuffer.put((byte) VERSION);
                    greetingsBuffer.put((byte) COMMAND);
                    client.write(ByteBuffer.wrap(greetingsBuffer.array(), 0, SIZEGREETINGS));
                    //this.greetingsBuffer = greetingsBuffer.array();
                    System.out.println("Got greetings message");
                    registred = true;
                    //gotRegister = true;
                    //writeClient();

                } else if (bytes == -1) {
                    System.out.println("Removing " + client.getRemoteAddress());

                    client.close();
                }
                byteBuffer.clear();
            } else {
                if (!connected) {
                    if (bytes > 0) {
                        int version = byteBuffer.get();
                        if (version != VERSION) {
                            throw new IOException("WRONG VERSION: " + version);
                        }

                        int command = byteBuffer.get();
                        if (command != TCPIP) {
                            throw new IOException("WRONG COMMAND: " + command);
                        }

                        int reserved = byteBuffer.get();
                        if (reserved != RESERVED) {
                            throw new IOException("WRONG RESERVED BYTE: " + reserved);
                        }

                        int addressType = byteBuffer.get();

                        if (addressType == IPV4) {

                            byte[] ip = new byte[SIZEIP];
                            byteBuffer.get(ip);
                            address = InetAddress.getByAddress(ip);

                        } else if (addressType == DNS) {

                            int len = byteBuffer.get();
                            byte[] byteName = new byte[len];
                            byteBuffer.get(byteName);
                            System.out.println("Domain name: " + new String(byteName));
                            String stringName = new String(byteName);
                            Name name = Name.fromString(stringName, Name.root);
                            Record record = Record.newRecord(name, Type.A, DClass.IN);
                            Message message = Message.newQuery(record);
                            dnsChannel.write(ByteBuffer.wrap(message.toWire()));
                            dns.put(message.getHeader().getID(), this);
                        } else {
                            throw new IOException("WRONG ADDRESS TYPE: " + addressType);
                        }

                        port = byteBuffer.getShort();
                        if (addressType == IPV4)
                            connect(address);

                    } else if (bytes == -1) {
                        System.out.println("Removing " + client.getRemoteAddress());

                        client.close();
                    }
                } else {
                    if (client.isConnected()) {
                        if (bytes > 0) {
                            //remoteBuffer = byteBuffer.array();
                            //writeRemote();
                            bytes = remote.write(ByteBuffer.wrap(byteBuffer.array(), 0, bytes));
                            System.out.println("Forwarded " + String.valueOf(bytes) + " bytes");
                        } else if (bytes == -1) {
                            System.out.println("Removing " + client.getRemoteAddress());

                            client.close();
                            remote.close();
                        }
                    }
                }
                byteBuffer.clear();
            }
        }

        void connect(InetAddress address) throws IOException {

            this.address = address;
            System.out.println("Address: " + this.address + ":" + port);

            remote = SocketChannel.open(new InetSocketAddress(this.address, port));
            ByteBuffer connectionBuffer = ByteBuffer.allocate(SIZECONNECTION);
            connectionBuffer.put((byte) VERSION);
            if (remote.isConnected()) {
                connectionBuffer.put((byte) OK);
            } else {
                connectionBuffer.put((byte) ERROR);
            }
            connectionBuffer.put((byte) RESERVED);
            connectionBuffer.put((byte) IPV4);
            connectionBuffer.put(InetAddress.getLocalHost().getAddress());
            connectionBuffer.putShort((short) serverPort);
            //this.connectionBuffer = connectionBuffer.array();
            //gotConnection = true;
            //writeClient();
            if (client.isConnected()) {
                client.write(ByteBuffer.wrap(connectionBuffer.array(), 0, SIZECONNECTION));
            }
            connectionBuffer.clear();
            if (!remote.isConnected()) {
                System.out.println("Removing " + client.getRemoteAddress());
                remote.close();
                client.close();
                return;
            }
            remote.configureBlocking(false);
            remote.register(selector, SelectionKey.OP_READ | SelectionKey.OP_CONNECT);
            remotes.put(remote, this);
            connected = true;
        }

        /*void writeClient() throws IOException {
            if (!registred && gotRegister) {
                int bytes = client.write(ByteBuffer.wrap(greetingsBuffer, 0, SIZEGREETINGS));
                if (bytes != SIZEGREETINGS) {
                    System.out.println("Removing " + client.getRemoteAddress());
                    client.close();
                } else {
                    registred = true;
                    System.out.println("Greetings: " + Arrays.toString(greetingsBuffer));
                }
            } else if (registred) {
                if (!connected && gotConnection) {
                    int bytes = client.write(ByteBuffer.wrap(connectionBuffer, 0, SIZECONNECTION));
                    if (bytes != SIZECONNECTION) {
                        System.out.println("Removing " + client.getRemoteAddress());
                        client.close();
                    } else {
                        connected = true;
                        System.out.println("Connection: " + Arrays.toString(connectionBuffer));
                    }
                } else if (connected && clientBuffer != null){
                    int bytes = client.write(ByteBuffer.wrap(clientBuffer, 0, clientBuffer.length));
                    if (bytes == -1) {
                        System.out.println("Removing " + client.getRemoteAddress());
                        client.close();
                    } else {
                        while (bytes < clientBuffer.length) {
                            bytes += client.write(ByteBuffer.wrap(clientBuffer, bytes, clientBuffer.length - bytes));
                        }
                        forwarded = true;
                    }
                }
            }
        }

        void writeRemote() throws IOException {
            if (remoteBuffer != null) {
                int bytes = remote.write(ByteBuffer.wrap(remoteBuffer, 0, remoteBuffer.length));
                if (bytes == -1) {
                    System.out.println("Removing " + client.getRemoteAddress());
                    client.close();
                } else {
                    while (bytes < remoteBuffer.length) {
                        bytes += remote.write(ByteBuffer.wrap(remoteBuffer, bytes, remoteBuffer.length - bytes));
                    }
                }
            }
        }*/
    }

    private Socks(String[] args) throws IOException {

        if (args.length != 1) {
            printHelp();
            getParams();
        } else {
            try {
                serverPort = Integer.parseInt(args[0]);
                if (serverPort > 65535 || serverPort < 0) throw new NumberFormatException();
            } catch (NumberFormatException ex) {
                System.out.println("Wrong argument. Port will be set to 1080");
                serverPort = 1080;
            }
        }

        selector = Selector.open();

        serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.bind(new InetSocketAddress(serverPort));
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

        String[] dnsServers = ResolverConfig.getCurrentConfig().servers();
        dnsChannel = DatagramChannel.open();
        dnsChannel.configureBlocking(false);
        if (dnsServers.length > 1) {
            dnsChannel.connect(new InetSocketAddress(dnsServers[1], 53));
        } else {
            dnsChannel.connect(new InetSocketAddress("8.8.8.8", 53));
        }
        dnsChannel.register(selector, SelectionKey.OP_READ);

        isRunning = true;
    }

    private void start() throws IOException {

        System.out.println("Proxy started working");

        while (isRunning) {

            selector.select();
            Set<SelectionKey> selectedKeys = selector.selectedKeys();

            for (SelectionKey key : selectedKeys) {
                if (key.isValid()) {
                    if (key.isAcceptable() && key.channel() == serverSocketChannel) {
                        register();
                    } else if (key.isConnectable()) {
                        ((SocketChannel) key.channel()).finishConnect();
                    } else if (key.isReadable()) {
                        receive(key);
                    } /*else if (key.isWritable()) {
                        write(key);
                    }*/
                }
            }
        }
    }

    /*private void write(SelectionKey key) throws IOException {

        ArrayList<Client> onRemove = new ArrayList<>();
        if (key.channel() instanceof SocketChannel) {
            SocketChannel socketChannel = (SocketChannel) key.channel();
            for (Client client : clients) {
                if (client.client.equals(socketChannel))
                    client.writeClient();
                if (!client.client.isConnected()) {
                    onRemove.add(client);
                }
            }
        }
        remove(onRemove);

    }*/

    private void remove(ArrayList<Client> onRemove) throws IOException {
        for (Client cl : onRemove) {
            if (cl.client.isConnected()) cl.client.close();
            if (cl.remote != null && cl.remote.isConnected()) cl.remote.close();
            clients.remove(cl.client);
            remotes.remove(cl.remote);
        }
    }

    private void receive(SelectionKey key) throws IOException {

        ArrayList<Client> onRemove = new ArrayList<>();
        if (key.channel() instanceof SocketChannel) {
            SocketChannel socketChannel = (SocketChannel) key.channel();
            Client client = clients.getOrDefault(socketChannel, null);
            if (client == null) {
                client = remotes.getOrDefault(socketChannel, null);
                if (client != null) {
                    client.newRemoteData();
                }
            } else {
                client.newClientData();
            }

        } else {
            if (key.channel().equals(dnsChannel)) {
                ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
                int length = dnsChannel.read(buffer);
                if (length > 0) {
                    System.out.println("Got " + length + " bytes from dns. Size: " + dns.size());
                    Message message = new Message(buffer.array());
                    Record[] records = message.getSectionArray(1);

                    for (Record record : records) {
                        if (record instanceof ARecord) {

                            ARecord aRecord = (ARecord) record;
                            int id = message.getHeader().getID();
                            Client cl = dns.get(id);
                            cl.connect(aRecord.getAddress());
                            if (!cl.client.isConnected()) {
                                onRemove.add(cl);
                            }
                            dns.remove(id);
                            break;
                        }
                    }
                    buffer.clear();
                }
            }
        }
        remove(onRemove);
    }

    private void register() throws IOException {

        SocketChannel socketChannel = serverSocketChannel.accept();
        if (socketChannel != null) {
            Client client = new Client(socketChannel);
            clients.put(socketChannel, client);
            socketChannel.register(selector, SelectionKey.OP_READ);
            System.out.println("Connection accepted: " + socketChannel.getRemoteAddress());
        }
    }

    private void getParams() {

        Scanner scanner = new Scanner(System.in);
        try {
            do {
                System.out.println("Write serverPort:");
            } while ((serverPort = Integer.parseInt(scanner.nextLine())) > 65535 || serverPort < 0);
        } catch (NumberFormatException ex) {
            System.out.println("Wrong argument. Port will be set to 1080");
            serverPort = 1080;
        }
        scanner.close();
    }

    private void printHelp() {

        System.out.println("Usage: java -jar Socks.jar [serverPort]");
        System.out.println("serverPort  Port where server is waiting on");

    }
}
