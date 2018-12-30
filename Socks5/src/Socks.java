import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;

import org.xbill.DNS.*;

public class Socks {

    private static final int BUFFER_SIZE = 8192;
    private int serverPort;
    private Selector selector;
    private ServerSocketChannel serverSocketChannel;
    private DatagramChannel dnsChannel;
    private boolean isRunning;
    private ArrayList<Client> clients = new ArrayList<>();
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
        InetAddress address = null;
        int port = 0;

        Client(SocketChannel channel) throws IOException {
            this.client = channel;
            client.configureBlocking(false);
        }

        void newRemoteData() throws IOException {

            ByteBuffer byteBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            if (remote.isConnected()) {
                int bytes = remote.read(byteBuffer);
                //System.out.println("Got " + bytes + " bytes from remote");
                if (bytes > 0) {
                    bytes = client.write(ByteBuffer.wrap(byteBuffer.array(), 0, bytes));
                    System.out.println("Forwarded " + bytes + " bytes to client");
                } else if (bytes == -1) {
                    System.out.println("Removing " + client.getRemoteAddress());

                    client.close();
                    remote.close();
                }
            }
            byteBuffer.clear();
        }

        void newClientData(Selector selector) throws IOException {
            ByteBuffer byteBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            int bytes = (client.isConnected()) ? client.read(byteBuffer) : -1;
            //System.out.println("Got " + bytes + " bytes from client");
            byteBuffer.flip();

            if (!registred) {
                if (bytes > 0) {

                    int version = byteBuffer.get();
                    if (version != 0x05) {
                        throw new IOException("WRONG VERSION: " + version);
                    }
                    //System.out.println("Version: " + version);

                    int commands = byteBuffer.get();
                    if (commands != 0x01) {
                        throw new IOException("WRONG NUMBER OF COMMANDS: " + commands);
                    }
                    //System.out.println("Number of commands: " + commands);

                    int command = byteBuffer.get();
                    if (command != 0x00) {
                        throw new IOException("WRONG COMMAND: " + command);
                    }
                    //System.out.println("Command " + command);

                    ByteBuffer outBuffer = ByteBuffer.allocate(2);
                    outBuffer.put((byte) 0x05);
                    outBuffer.put((byte) 0x00);
                    System.out.println("Send back: " + Arrays.toString(outBuffer.array()));
                    int len = client.write(ByteBuffer.wrap(outBuffer.array(), 0, 2));
                    outBuffer.clear();
                    System.out.println("Got greetings message");

                    registred = true;

                } else if (bytes == -1) {
                    System.out.println("Removing " + client.getRemoteAddress());

                    client.close();
                }
                byteBuffer.clear();
            } else {
                if (!connected) {
                    if (bytes > 0) {
                        int version = byteBuffer.get();
                        if (version != 0x05) {
                            throw new IOException("WRONG VERSION: " + version);
                        }
                        //System.out.println("Version: " + version);

                        int command = byteBuffer.get();
                        if (command != 0x01) {
                            throw new IOException("WRONG COMMAND: " + command);
                        }
                        //System.out.println("Command " + command);

                        int reserved = byteBuffer.get();
                        if (reserved != 0x00) {
                            throw new IOException("WRONG RESERVED BYTE: " + reserved);
                        }
                        //System.out.println("Byte " + reserved);

                        int addressType = byteBuffer.get();
                        //System.out.println("Address type: " + addressType);

                        if (addressType == 0x01) {

                            byte[] ip = new byte[4];
                            byteBuffer.get(ip);
                            address = InetAddress.getByAddress(ip);
                            //System.out.println("Address: " + address);

                        } else if (addressType == 0x03) {

                            int len = byteBuffer.get();
                            byte[] byteName = new byte[len];
                            byteBuffer.get(byteName);
                            System.out.println("Domain name: " + new String(byteName));
                            String stringName = new String(byteName);
                            //address = InetAddress.getByName(new String(byteName));
                            Name name = Name.fromString(stringName, Name.root);
                            Record record = Record.newRecord(name, Type.A, DClass.IN);
                            Message message = Message.newQuery(record);
                            len = dnsChannel.write(ByteBuffer.wrap(message.toWire()));
                            dns.put(message.getHeader().getID(), this);
                            //System.out.println("Wrote to dns " + len + " bytes. Size: " + dns.size());
                        } else {
                            throw new IOException("WRONG ADDRESS TYPE: " + addressType);
                        }

                        port = byteBuffer.getShort();
                        //System.out.println("Port: " + port);
                        if (addressType == 0x01)
                            connect(address);

                    } else if (bytes == -1) {
                        System.out.println("Removing " + client.getRemoteAddress());

                        client.close();
                    }
                    byteBuffer.clear();
                } else {
                    if (client.isConnected()) {
                        if (bytes > 0) {
                            bytes = remote.write(ByteBuffer.wrap(byteBuffer.array(), 0, bytes));
                            System.out.println("Forwarded " + String.valueOf(bytes) + " bytes");
                        } else if (bytes == -1) {
                            System.out.println("Removing " + client.getRemoteAddress());

                            client.close();
                            remote.close();
                        }
                    }
                    byteBuffer.clear();
                }
            }
        }

        void connect(InetAddress address) throws IOException {

            this.address = address;
            System.out.println("Address: " + this.address + ":" + port);

            remote = SocketChannel.open(new InetSocketAddress(this.address, port));
            ByteBuffer outBuffer = ByteBuffer.allocate(10);
            outBuffer.put((byte) 0x05);
            if (remote.isConnected()) {
                outBuffer.put((byte) 0x00);
            } else {
                outBuffer.put((byte) 0x01);
            }
            outBuffer.put((byte) 0x00);
            outBuffer.put((byte) 0x01);
            outBuffer.put(InetAddress.getLocalHost().getAddress());
            outBuffer.putShort((short) serverPort);

            System.out.println("Send back: " + Arrays.toString(outBuffer.array()));

            int len = client.write(ByteBuffer.wrap(outBuffer.array(), 0, 10));
            outBuffer.clear();
            if (!remote.isConnected()) {
                System.out.println("Removing " + client.getRemoteAddress());
                remote.close();
                client.close();
                return;
            }
            remote.configureBlocking(false);
            remote.register(selector, SelectionKey.OP_READ);
            connected = true;

        }
    }

    private Socks(String[] args) throws IOException {

        if (args.length != 1) {
            printHelp();
            getParams();
        } else {
            serverPort = Integer.parseInt(args[0]);
        }

        selector = Selector.open();

        serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.bind(new InetSocketAddress(serverPort));
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

        String[] dnsServers = ResolverConfig.getCurrentConfig().servers();
        dnsChannel = DatagramChannel.open();
        dnsChannel.configureBlocking(false);
        if (dnsServers.length != 0) {
            dnsChannel.connect(new InetSocketAddress(dnsServers[0], 53));
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
                    }
                }
            }
        }
    }

    private void receive(SelectionKey key) throws IOException {

        ArrayList<Client> onRemove = new ArrayList<>();
        if (key.channel() instanceof SocketChannel) {
            SocketChannel socketChannel = (SocketChannel) key.channel();
            for (Client client : clients) {
                if (client.remote != null && client.remote.equals(socketChannel))
                    client.newRemoteData();
                else if (client.client.equals(socketChannel))
                    client.newClientData(selector);
                if (!client.client.isConnected()) {
                    onRemove.add(client);
                }
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
                            //System.out.println(aRecord.getAddress());
                            cl.connect(aRecord.getAddress());
                            if (!cl.client.isConnected()) {
                                onRemove.add(cl);
                            }
                            dns.remove(id);
                        }
                    }
                    buffer.clear();
                }
            }
        }
        for (Client cl : onRemove) {
            if (cl.client.isConnected()) cl.client.close();
            if (cl.remote != null && cl.remote.isConnected()) cl.remote.close();
            clients.remove(cl);
        }
    }

    private void register() throws IOException {

        SocketChannel socketChannel = serverSocketChannel.accept();
        if (socketChannel != null) {
            Client client = new Client(socketChannel);
            clients.add(client);
            socketChannel.register(selector, SelectionKey.OP_READ);
            System.out.println("Connection accepted: " + socketChannel.getRemoteAddress());
        }
    }

    private void getParams() {

        System.out.println("Write serverPort:");
        Scanner scanner = new Scanner(System.in);
        serverPort = Integer.parseInt(scanner.nextLine());
        scanner.close();
    }

    private void printHelp() {

        System.out.println("Usage: java -jar Socks.jar [serverPort]");
        System.out.println("serverPort  Port where server is waiting on");

    }
}
