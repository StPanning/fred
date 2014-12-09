package freenet.node;

public interface JFKHandshakeInterface {
    public void send(AbstractJFKMessage m);
    public void send(JFKMessage1 m);
    public void send(JFKMessage3 m);
    public void send(JFKMessage3Cached m);

};
