package com.exadel.certificates.util;


import org.bouncycastle.openssl.PEMWriter;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

public class PemUtils {

    private PemUtils() {

    }

    public static void saveAsFile(Object savingObject, String path) throws IOException {
        PEMWriter pemWriter = new PEMWriter(new PrintWriter(new File(path)));
        pemWriter.writeObject(savingObject);
        pemWriter.close();
    }
}
