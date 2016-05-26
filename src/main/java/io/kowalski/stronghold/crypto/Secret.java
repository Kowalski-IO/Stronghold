package io.kowalski.stronghold.crypto;

import java.io.Serializable;

import lombok.Data;

@Data
public class Secret implements Serializable {

    private static final long serialVersionUID = 7872611417757995620L;

    private final byte[] iv;
    private final byte[] cipherText;

}
