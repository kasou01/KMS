package com.sample;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Base64;

public class KMSExample {
    final static Charset charset = StandardCharsets.UTF_8;
    final static String key = "";
    final static String secretKey = "";
    final static String keyArn = "";

    public KmsClient kmsClient;

    public KMSExample() {

        AwsBasicCredentials awsCreds = AwsBasicCredentials.create(key, secretKey);
        this.kmsClient = KmsClient.builder().credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .region(Region.US_EAST_1).build();

    }

    public void encryptUsingDataKey(SdkBytes jsonString) {
        try {
            GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest.builder().keyId(keyArn)
                    .keySpec(DataKeySpec.AES_128).build();
            GenerateDataKeyResponse generateDataKeyResponse = this.kmsClient.generateDataKey(generateDataKeyRequest);

            SecretKeySpec key = new SecretKeySpec(generateDataKeyResponse.plaintext().asByteArray(), "AES");
            Cipher cipher;
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encodedSecret = cipher.doFinal(jsonString.asByteArray());

            String path = Paths.get(".").toAbsolutePath().normalize().toString() + "/observation_datakey_encrypt.json";
            KMSExample.writeToFile(SdkBytes.fromByteArray(encodedSecret), path);

            path = Paths.get(".").toAbsolutePath().normalize().toString() + "/data_key_encrypt.txt";
            KMSExample.writeToFile(generateDataKeyResponse.ciphertextBlob(), path);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void decryptUsingDataKey()
    {
        try {
            String path = Paths.get(".").toAbsolutePath().normalize().toString() + "/data_key_encrypt.txt";
            SdkBytes sdkBytes = KMSExample.readFromFile(path);

            DecryptRequest decryptRequest = DecryptRequest.builder().ciphertextBlob(sdkBytes).build();
            DecryptResponse decryptResponse = this.kmsClient.decrypt(decryptRequest);

            SecretKeySpec secretKeySpec = new SecretKeySpec(decryptResponse.plaintext().asByteArray(), "AES");

            path = Paths.get(".").toAbsolutePath().normalize().toString() + "/observation_datakey_encrypt.json";
            sdkBytes = KMSExample.readFromFile(path);

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            System.out.println(SdkBytes.fromByteArray(cipher.doFinal(sdkBytes.asByteArray())).asUtf8String());

        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }

    public SdkBytes encrypt(SdkBytes jsonString) {
        EncryptRequest encryptRequest = EncryptRequest.builder().keyId(keyArn).plaintext(jsonString).build();
        EncryptResponse encryptResponse = this.kmsClient.encrypt(encryptRequest);
        return encryptResponse.ciphertextBlob();

    }

    public SdkBytes deCrypt(SdkBytes encryptedJsonString) {
        DecryptRequest decryptRequest = DecryptRequest.builder().ciphertextBlob(encryptedJsonString).build();
        DecryptResponse decryptResponse = this.kmsClient.decrypt(decryptRequest);
        return decryptResponse.plaintext();
    }

    public static void main(String[] args) {
        try {
            KMSExample kmsExample = new KMSExample();
            InputStream in = kmsExample.getClass().getClassLoader().getResourceAsStream("observation.json");

            SdkBytes inputBytes = SdkBytes.fromInputStream(in);
            SdkBytes outputBytes = kmsExample.encrypt(inputBytes);

            String path = Paths.get(".").toAbsolutePath().normalize().toString() + "/observation_encrypt.json";

            KMSExample.writeToFile(outputBytes, path);

            SdkBytes output2Bytes = kmsExample.deCrypt(KMSExample.readFromFile(path));

            System.out.println(output2Bytes.asUtf8String());

            kmsExample.encryptUsingDataKey(inputBytes);

            kmsExample.decryptUsingDataKey();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void writeToFile(SdkBytes bytesToWrite, String path) throws IOException {
        FileChannel fc;

        FileOutputStream outputStream = new FileOutputStream(path);
        fc = outputStream.getChannel();

        fc.write(bytesToWrite.asByteBuffer());
        outputStream.close();
        fc.close();
    }

    public static SdkBytes readFromFile(String path) throws IOException {

        InputStream in2 = new FileInputStream(path);
        return SdkBytes.fromInputStream(in2);
    }
    public static String encode(String target){
        if(target == null || target.length() == 0){
            throw new IllegalArgumentException("Error: String length must > 0");
        }else{
            StringBuffer sb = new StringBuffer(target);
            String dst = sb.reverse().toString();
            byte[] encode = Base64.getEncoder().encode(dst.getBytes(charset));
            String s = new String(encode, charset);
            StringBuffer sb2 = new StringBuffer(s);
            return sb2.reverse().toString();
        }
    }
    public static String decode(String target){
        if(target == null || target.length() == 0){
            throw new IllegalArgumentException("Error: String length must > 0");
        }else{
            StringBuffer s = new StringBuffer(target);
            String dst = s.reverse().toString();
            byte[] decode = Base64.getUrlDecoder().decode(dst.getBytes(charset));
            String temp = new String(decode,charset);
            StringBuffer sb = new StringBuffer(temp);
            return sb.reverse().toString();
        }
    }

}