import org.xbill.DNS.*;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

class Client {

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

    SocketChannel client, remote;
    private boolean connected = false;
    private boolean registred = false;
    private InetAddress address = null;
    private int port = 0;

    Client(SocketChannel channel) throws IOException {
        this.client = channel;
        client.configureBlocking(false);
    }

    void newRemoteData() throws IOException {

        ByteBuffer byteBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        try {
            if (remote.isConnected()) {
                int bytes = remote.read(byteBuffer);
                if (bytes > 0) {
                    bytes = client.write(ByteBuffer.wrap(byteBuffer.array(), 0, bytes));
                    //System.out.println("Forwarded " + bytes + " bytes to client");
                } else if (bytes == -1) {
                    throw new IOException("Removing " + client.getRemoteAddress());
                }
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());

            if (client.isConnected())
                client.close();
            if (remote.isConnected())
                remote.close();
        } finally {
            byteBuffer.clear();
        }
    }

    void newClientData() throws IOException {

        ByteBuffer byteBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        try {
            int bytes = client.read(byteBuffer);
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
                    greetingsBuffer.clear();
                    //System.out.println("Got greetings message");
                    registred = true;

                } else if (bytes == -1) {
                    throw new IOException("Removing " + client.getRemoteAddress());
                }
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
                            //System.out.println("Domain name: " + new String(byteName));
                            String stringName = new String(byteName);
                            Name name = Name.fromString(stringName, Name.root);
                            Record record = Record.newRecord(name, Type.A, DClass.IN);
                            Message message = Message.newQuery(record);
                            Socks.dnsChannel.write(ByteBuffer.wrap(message.toWire()));
                            Socks.dns.put(message.getHeader().getID(), this);
                        } else {
                            throw new IOException("WRONG ADDRESS TYPE: " + addressType);
                        }

                        port = byteBuffer.getShort();
                        if (addressType == IPV4)
                            connect(address);

                    } else if (bytes == -1) {
                        throw new IOException("Removing " + client.getRemoteAddress());
                    }
                } else {
                    if (client.isConnected()) {
                        if (bytes > 0) {
                            bytes = remote.write(ByteBuffer.wrap(byteBuffer.array(), 0, bytes));
                            //System.out.println("Forwarded " + String.valueOf(bytes) + " bytes");
                        } else if (bytes == -1) {
                            throw new IOException("Removing " + client.getRemoteAddress());
                        }
                    }
                }
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
            if (client.isConnected())
                client.close();
            if (remote != null && remote.isConnected())
                remote.close();
        } finally {
            byteBuffer.clear();
        }
    }

    void connect(InetAddress address) throws IOException {

        try {
            if (client.isConnected()) {
                this.address = address;
                //System.out.println("Address: " + this.address + ":" + port);

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
                connectionBuffer.putShort((short) Socks.serverPort);

                client.write(ByteBuffer.wrap(connectionBuffer.array(), 0, SIZECONNECTION));
                connectionBuffer.clear();

                if (!remote.isConnected()) {
                    throw new IOException("Removing " + client.getRemoteAddress());
                }
                remote.configureBlocking(false);
                remote.register(Socks.selector, SelectionKey.OP_READ | SelectionKey.OP_CONNECT);
                Socks.remotes.put(remote, this);
                connected = true;
            }
        } catch (ClosedChannelException | ConnectException e) {
            System.out.println(e.getMessage());
            if (client.isConnected())
                client.close();
            if (remote != null && remote.isConnected())
                remote.close();
        }
    }
}