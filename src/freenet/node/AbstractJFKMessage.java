package freenet.node;

public abstract class AbstractJFKMessage {
    AbstractJFKMessage(){
    }
    //dispatching avoids casts
    public abstract void send(JFKHandshakeInterface ji);
}
