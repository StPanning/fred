package freenet.node;

public interface CipherSpecs {
        public int
        getNonceSize();
        public int
        getSignatureLength();
        public int
        getModulusLength();
}
