package rsa;

import java.math.BigInteger;

public class PublicKey implements java.io.Serializable {

    /**
     * Represents a Public Key
     */
    private static final long serialVersionUID = 1L;
    private BigInteger n, e;

    public PublicKey(BigInteger n, BigInteger e) {
        this.setN(n);
        this.setE(e);
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

}
