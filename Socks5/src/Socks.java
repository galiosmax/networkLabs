import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;

import org.xbill.DNS.*;

public class Socks {

    private final static int BUFFER_SIZE = 8192;

    static int serverPort;
    static Selector selector;
    private static ServerSocketChannel serverSocketChannel;
    static DatagramChannel dnsChannel;
    private boolean isRunning;
    private static HashMap<SocketChannel, Client> clients = new HashMap<>();
    static HashMap<SocketChannel, Client> remotes = new HashMap<>();
    static HashMap<Integer, Client> dns = new HashMap<>();

    public static void main(String[] args) {

        Socks server;
        try {
            server = new Socks(args);
            server.start();
        } catch (IOException e) {
            e.printStackTrace();
        }

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
        System.out.println(dnsServers.length);
        for (String server : dnsServers) {
            System.out.println(server);
        }
        if (dnsServers.length > 2) {
            dnsChannel.connect(new InetSocketAddress(dnsServers[2], 53));
        } else {
            dnsChannel.connect(new InetSocketAddress("8.8.8.8", 53));
        }
        dnsChannel.register(selector, SelectionKey.OP_READ);

        isRunning = true;
    }

    private void start() throws IOException {

        System.out.println("Proxy started working");

        try {
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
        } finally {
            for (SocketChannel channel : clients.keySet()) {
                channel.close();
            }
            for (SocketChannel channel : remotes.keySet()) {
                channel.close();
            }
            serverSocketChannel.close();
            dnsChannel.close();
            selector.close();
        }
    }

    private void remove(ArrayList<Client> onRemove) {
        try {
            for (Client cl : onRemove) {
                if (cl.client.isConnected()) cl.client.close();
                if (cl.remote != null && cl.remote.isConnected()) cl.remote.close();
                clients.remove(cl.client);
                remotes.remove(cl.remote);
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void receive(SelectionKey key) {

        try {
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
                                try {
                                    cl.connect(aRecord.getAddress());
                                    if (!cl.client.isConnected()) {
                                        onRemove.add(cl);
                                    }
                                } catch (NullPointerException e) {
                                    System.out.println("Exception: address " + aRecord.getAddress());
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
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void register() {
        try {
            SocketChannel socketChannel = serverSocketChannel.accept();
            if (socketChannel != null) {
                Client client = new Client(socketChannel);
                clients.put(socketChannel, client);
                socketChannel.register(selector, SelectionKey.OP_READ);
                System.out.println("Connection accepted: " + socketChannel.getRemoteAddress());
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
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
