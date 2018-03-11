import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Main {

    private static final String keystorePath = "digi_cer.p12";
    private static final char[] password = "123456".toCharArray();

    private static Certificate[] chain;
    private static PrivateKey pk;

    private static void init() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException {
        Security.addProvider(new BouncyCastleProvider());
        pk = Pkcs12FileHelper.readFirstKey(keystorePath, password, password);
        chain = Pkcs12FileHelper.readFirstChain(keystorePath, password);
    }

    private static void textAutoscaleTest01() throws GeneralSecurityException, IOException, InterruptedException {
        String fileName = "textAutoscaleTest01.pdf";

        Rectangle rect = new Rectangle(36, 648, 200, 100);
        signatureAppearanceAutoscale(fileName, rect, PdfSignatureAppearance.RenderingMode.DESCRIPTION);
    }

    private static void textAutoscaleTest02() throws GeneralSecurityException, IOException, InterruptedException {
        String fileName = "textAutoscaleTest02.pdf";

        Rectangle rect = new Rectangle(36, 648, 100, 50);
        signatureAppearanceAutoscale(fileName, rect, PdfSignatureAppearance.RenderingMode.DESCRIPTION);
    }

    private static void textAutoscaleTest03() throws GeneralSecurityException, IOException, InterruptedException {
        String fileName = "textAutoscaleTest03.pdf";

        Rectangle rect = new Rectangle(36, 648, 200, 100);
        signatureAppearanceAutoscale(fileName, rect, PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION);
    }

    private static void textAutoscaleTest04() throws GeneralSecurityException, IOException, InterruptedException {
        String fileName = "textAutoscaleTest04.pdf";

        Rectangle rect = new Rectangle(36, 648, 100, 50);
        signatureAppearanceAutoscale(fileName, rect, PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION);
    }

    private static void textAutoscaleTest05() throws GeneralSecurityException, IOException, InterruptedException {
        String fileName = "textAutoscaleTest05.pdf";

        Rectangle rect = new Rectangle(36, 648, 200, 100);
        signatureAppearanceAutoscale(fileName, rect, PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
    }

    private static void textAutoscaleTest06() throws GeneralSecurityException, IOException, InterruptedException {
        String fileName = "textAutoscaleTest06.pdf";

        Rectangle rect = new Rectangle(36, 648, 100, 50);
        signatureAppearanceAutoscale(fileName, rect, PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
    }

    private static void signatureAppearanceAutoscale(String dest, Rectangle rect, PdfSignatureAppearance.RenderingMode renderingMode) throws IOException, GeneralSecurityException {
        String src = "simpleDocument.pdf";

        PdfSigner signer = new PdfSigner(new PdfReader(src), new FileOutputStream(dest), false);
        // Creating the appearance
        signer.getSignatureAppearance()
                .setLayer2FontSize(0)
                .setReason("Test 1")
                .setLocation("TestCity")
                .setPageRect(rect)
                .setRenderingMode(renderingMode)
                .setSignatureGraphic(ImageDataFactory.create("itext.png"));

        signer.setFieldName("Signature1");
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, BouncyCastleProvider.PROVIDER_NAME);
        signer.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
    }


    public static void main(String[] args) throws InterruptedException, GeneralSecurityException, IOException {
        init();
        textAutoscaleTest01();
        textAutoscaleTest02();
        textAutoscaleTest03();
        textAutoscaleTest04();
        textAutoscaleTest05();
        textAutoscaleTest06();
    }
}
