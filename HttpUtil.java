package com.xyebank.exchange.util;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.UnsupportedCharsetException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import com.alibaba.fastjson.JSONObject;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.*;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.net.URLEncoder;

import javax.net.ssl.*;

/**
 * Created by DK on 2016/11/1.
 */
public class HttpUtil {
    private static PoolingHttpClientConnectionManager cm;
    private RequestConfig requestConfig;
    private final static int defaultTimeout = 240000;
    private String EMPTY_STR = "";
    private CloseableHttpClient httpClient;
    private HttpHost proxy;
    private static SSLConnectionSocketFactory socketFactory;

    public String requestEncoding = "UTF-8";
    public String responseEncoding = "UTF-8";
    public Map<String, String> headers;
    public Boolean autoRedirect = true;
    public long sleepTime = 50;

    private static ArrayList<NameValuePair> covertParams2NVPS(Map<String, String> params) {
        ArrayList<NameValuePair> pairs = new ArrayList<>();
        for (Map.Entry<String, String> param : params.entrySet()) {
            pairs.add(new BasicNameValuePair(param.getKey(), String.valueOf(param.getValue())));
        }
        return pairs;
    }

    /**
     * 设置信任自定义的证书
     *
     * @param keyStorePath 密钥库路径
     * @param keyStorepass 密钥库密码
     * @return
     */
    private static void enableCustomVerifySSL(String keyStorePath, String keyStorepass) {
        FileInputStream instream = null;
        try {
            SSLContext sc;
            KeyStore trustStore;
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            instream = new FileInputStream(new File(keyStorePath));
            trustStore.load(instream, keyStorepass.toCharArray());
            // 相信自己的CA和所有自签名的证书
            sc = SSLContexts.custom().loadTrustMaterial(trustStore, new TrustSelfSignedStrategy()).build();
            socketFactory = new SSLConnectionSocketFactory(sc, NoopHostnameVerifier.INSTANCE);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } finally {
            try {
                instream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 忽略证书
     */
    private static void IgnoreVerifySSL() {
        try {
            TrustManager manager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };
            SSLContext context = SSLContext.getInstance("TLS");//SSLv3
            context.init(null, new TrustManager[]{manager}, null);
            socketFactory = new SSLConnectionSocketFactory(context, NoopHostnameVerifier.INSTANCE);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }

    private void initHttpClient() {
        requestConfig = RequestConfig.custom()
                .setSocketTimeout(defaultTimeout)
                .setConnectTimeout(defaultTimeout)
                .setConnectionRequestTimeout(defaultTimeout)
                .setCookieSpec(CookieSpecs.STANDARD_STRICT)
                .setRedirectsEnabled(false)
                .setExpectContinueEnabled(true)
                .setTargetPreferredAuthSchemes(Arrays.asList(AuthSchemes.NTLM, AuthSchemes.DIGEST))
                .setProxyPreferredAuthSchemes(Arrays.asList(AuthSchemes.BASIC))
                .build();

        if (cm == null) {
            IgnoreVerifySSL();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("http", PlainConnectionSocketFactory.INSTANCE)
                    .register("https", socketFactory).build();
            cm = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
            cm.setMaxTotal(500);// 整个连接池最大连接数
            cm.setDefaultMaxPerRoute(5);// 每路由最大连接数，默认值是2
        }

        reSetHeader();

        DefaultHttpRequestRetryHandler dhr = new DefaultHttpRequestRetryHandler(3, true);
        httpClient = HttpClients.custom().setConnectionManager(cm).setRetryHandler(dhr)
                .build();

    }

    public void reSetHeader() {
        headers = new HashMap<>();
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;application/json;q=0.9,image/webp,*/*;q=0.8");
        headers.put("Accept-Encoding", "gzip, deflate, sdch, br");
        headers.put("Accept-Language", "zh-CN,zh;q=0.8");
        headers.put("Upgrade-Insecure-Requests", "1");
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36");
    }

    private String getResult(HttpRequestBase request) {
        for (Map.Entry<String, String> param : headers.entrySet()) {
            request.addHeader(param.getKey(), String.valueOf(param.getValue()));
        }
        request.setConfig(requestConfig);
        CloseableHttpResponse response = null;
        try {
            if (proxy == null) {
                response = httpClient.execute(request);
                Thread.sleep(sleepTime);
            } else {
                response = httpClient.execute(proxy, request);
                Thread.sleep(sleepTime);
            }
            int statusCode = response.getStatusLine().getStatusCode();

            if (autoRedirect) {
                int i = 0;
                while (statusCode == HttpStatus.SC_MOVED_PERMANENTLY || statusCode == HttpStatus.SC_MOVED_TEMPORARILY) {
                    if (i > 10) {
                        break;
                    }
                    Header locationHeader = response.getFirstHeader("Location");
                    if (locationHeader != null) {
                        String redirectUrl = locationHeader.getValue();

                        request.releaseConnection();
                        request = new HttpGet(redirectUrl);
                        for (Map.Entry<String, String> param : headers.entrySet()) {
                            request.addHeader(param.getKey(), String.valueOf(param.getValue()));
                        }
                        request.setConfig(requestConfig);

                        if (proxy == null) {
                            response = httpClient.execute(request);
                            Thread.sleep(sleepTime);
                        } else {
                            response = httpClient.execute(proxy, request);
                            Thread.sleep(sleepTime);
                        }

                        statusCode = response.getStatusLine().getStatusCode();
                    }
                    i++;
                }
            }
            int j = 2;
            while (statusCode != HttpStatus.SC_OK && statusCode != HttpStatus.SC_NOT_FOUND) {
                if (j > 3) {
                    break;
                }
                request.releaseConnection();
                if (proxy == null) {
                    response = httpClient.execute(request);
                    Thread.sleep(sleepTime);
                } else {
                    response = httpClient.execute(proxy, request);
                    Thread.sleep(sleepTime);
                }

                statusCode = response.getStatusLine().getStatusCode();

                j++;
            }

            if (statusCode == HttpStatus.SC_OK) {
                String result = EntityUtils.toString(response.getEntity(), responseEncoding);
                return result;
            } else {
                String result = EntityUtils.toString(response.getEntity(), responseEncoding);
                return "HTTPSTATUS_ERROR:" + statusCode + "::::" + result;
            }
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (HttpHostConnectException e) {
            e.printStackTrace();
            return "HTTPSTATUS_ERROR:TIME OUT";
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            request.releaseConnection();
            try {
                if (response != null) {
                    response.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return EMPTY_STR;
    }

    public HttpUtil() {
        initHttpClient();
    }

    public void setProxy(String host, int port) {
        proxy = new HttpHost(host, port);
    }

    public void enableFidder() {
        proxy = new HttpHost("127.0.0.1", 8888);
    }

    public void disableProxy() {
        proxy = null;
    }

    public String doGet(String url) {
        HttpGet httpGet = new HttpGet(url);
        return getResult(httpGet);
    }

    public String doGetMap(String url, Map<String, String> params) {
        String result = "";
        try {
            URIBuilder ub = new URIBuilder();
            ub.setPath(url);

            ArrayList<NameValuePair> pairs = covertParams2NVPS(params);
            ub.setParameters(pairs);

            HttpGet httpGet = new HttpGet(ub.build());
            result = getResult(httpGet);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        return result;
    }

    public String doPost(String url) {
        HttpPost httpPost = new HttpPost(url);
        return getResult(httpPost);
    }

    public String doPostMap(String url, Map<String, String> params) {
        String result = "";
        try {
            HttpPost httpPost = new HttpPost(url);
            ArrayList<NameValuePair> pairs = covertParams2NVPS(params);
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(pairs, requestEncoding);
            entity.setContentEncoding(requestEncoding);
            httpPost.setEntity(entity);
            result = getResult(httpPost);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return result;
    }

    public String doPostStr(String url, String postStr) {
        String result = "";

        try {
            HttpPost httpPost = new HttpPost(url);
            StringEntity stringEntity = new StringEntity(postStr, requestEncoding);//解决中文乱码问题
            stringEntity.setContentEncoding(requestEncoding);
            stringEntity.setContentType("application/x-www-form-urlencoded");
            httpPost.setEntity(stringEntity);
            result = getResult(httpPost);
        } catch (UnsupportedCharsetException e) {
            e.printStackTrace();
        }

        return result;
    }

    public String doPostJson(String url, String jsonStr) {
        String result = "";
        try {
            HttpPost httpPost = new HttpPost(url);
            StringEntity stringEntity = new StringEntity(jsonStr, requestEncoding);//解决中文乱码问题
            stringEntity.setContentEncoding(requestEncoding);
            stringEntity.setContentType("application/json;charset=UTF-8");
            httpPost.setEntity(stringEntity);
            result = getResult(httpPost);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;

    }
        String test = "12345678" + "" + "" + timestamp;
        StringBuilder localStringBuilder;
        try {
            byte[] arrayOfByte = MessageDigest.getInstance("MD5").digest(test.getBytes("UTF-8"));
            localStringBuilder = new StringBuilder(2 * arrayOfByte.length);
            int i = arrayOfByte.length;
            for (int j = 0; j < i; j++) {
                int k = arrayOfByte[j];
                if ((k & 0xFF) < 16)
                    localStringBuilder.append("0");
                localStringBuilder.append(Integer.toHexString(k & 0xFF));
            }
        } catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {
            throw new RuntimeException("MD5 should not be supported!", localNoSuchAlgorithmException);
        } catch (UnsupportedEncodingException localUnsupportedEncodingException) {
            throw new RuntimeException("UTF-8 should not be supported!", localUnsupportedEncodingException);
        }
        return localStringBuilder.toString().toUpperCase();
    }

    public static void main(String[] args) {

    }

}
