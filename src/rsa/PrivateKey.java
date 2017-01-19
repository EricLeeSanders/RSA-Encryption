package rsa;

import java.math.BigInteger;

public class PrivateKey implements java.io.Serializable {
    /**
     * Represents a Private Key
     */
    private static final long serialVersionUID = 1L;
    private BigInteger n, d, p, q;

    public PrivateKey(BigInteger n, BigInteger d, BigInteger p, BigInteger q) {
        this.setN(n);
        this.setD(d);
        this.setP(p);
        this.setQ(q);
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }
}
