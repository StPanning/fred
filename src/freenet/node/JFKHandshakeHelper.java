package freenet.node;
import freenet.io.comm.Peer;
import net.i2p.util.NativeBigInteger;
import freenet.crypt.DiffieHellman;
import freenet.crypt.DiffieHellmanLightContext;
import freenet.support.Logger;

// this class exists to keep the API changes
// to FNPPacketMangler inside FNPPacketMangler
// and to keep them specific/small.
// it allows that the public interface of FNPPacketMangler
// doesn't change.
// it exists to store temporary
// handshake-specific variables.
// further refactorings may deprecate this class.

public class JFKHandshakeHelper
    implements JFKHandshakeInterface{

    private FNPPacketMangler m_pm;
    private PeerNode         m_peerNode;
    private Peer             m_peer;
    private int              m_negType;

    public JFKHandshakeHelper(FNPPacketMangler pm,
                              PeerNode pn, Peer peer,
                              int negType){
        m_pm       = pm;
        m_peerNode = pn;
        m_peer     = peer;
        m_negType  = negType;
    }


    //dispatching avoids casts
    public void send(AbstractJFKMessage m){
        m.send(this);
    }

    public void send(JFKMessage1 m){
        boolean dh_ok = DiffieHellman.checkDHExponentialValidity(
        m_pm.getClass(), new NativeBigInteger(1, m.getPeerExponent()));

        if(m_negType >= 8 || dh_ok){
            // JFK protects us from weak key attacks on ECDH, so we don't need to check.
            try {
                m_pm.sendJFKMessage1(m_peerNode,
                                     m_peer,
                                     m.istUnknownInitiator(),
                                     m.getSetupType(),
                                     m_negType);

            } catch (FNPPacketMangler.NoContextsException e) {
                m_pm.handleNoContextsException(e,
                  FNPPacketMangler.NoContextsException.CONTEXT.REPLYING);
                return;
            }
        } else {
            Logger.error(this, "We can't accept the exponential "+
                         m_peerNode +
                         " sent us!! REDFLAG: IT CAN'T HAPPEN UNLESS AGAINST AN ACTIVE ATTACKER!!");
        }
    }

    public void send(JFKMessage3 m){

    }

    public void send(JFKMessage3Cached m){

    }
}
