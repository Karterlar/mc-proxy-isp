using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;

namespace McProxyOffline {
  public sealed class Result {
    public bool success;
    public string code;
    public long elapsedMs;
    public string localAddress;
    public string certificateSha256;
    public string exceptionType;
    public int statusCode;
    // Body exists only in memory to parse an IP. PowerShell must never log it.
    public string body;
  }
  public static class Transport {
    public static Result Relay(string address, int port, string serverName, string pin, int timeoutMs) {
      Result result = new Result { code = "RELAY_UNREACHABLE" };
      Stopwatch watch = Stopwatch.StartNew();
      TcpClient client = null;
      bool certificateRejected = false;
      try {
        IPAddress ip = IPAddress.Parse(address);
        client = new TcpClient(ip.AddressFamily);
        IAsyncResult connecting = client.BeginConnect(ip, port, null, null);
        using (System.Threading.WaitHandle wait = connecting.AsyncWaitHandle) {
          if (!wait.WaitOne(timeoutMs)) { result.code = "RELAY_TIMEOUT"; return result; }
          client.EndConnect(connecting);
        }
        result.localAddress = ((IPEndPoint)client.Client.LocalEndPoint).Address.ToString();
        result.code = "RELAY_TLS_FAILED";
        NetworkStream network = client.GetStream();
        network.ReadTimeout = timeoutMs; network.WriteTimeout = timeoutMs;
        RemoteCertificateValidationCallback validate = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
          certificateRejected = true;
          if (certificate == null) return false;
          using (SHA256 hash = SHA256.Create()) {
            result.certificateSha256 = BitConverter.ToString(hash.ComputeHash(certificate.GetRawCertData())).Replace("-", "");
          }
          if (!String.Equals(result.certificateSha256, pin, StringComparison.OrdinalIgnoreCase)) return false;
          using (X509Certificate2 leaf = new X509Certificate2(certificate)) {
            DateTime now = DateTime.UtcNow;
            if (now < leaf.NotBefore.ToUniversalTime() || now > leaf.NotAfter.ToUniversalTime()) return false;
          }
          if ((errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
          // A private self-signed certificate is trusted only by its exact leaf
          // fingerprint AND hostname/date checks. There is no insecure fallback.
          certificateRejected = false;
          return true;
        };
        using (SslStream tls = new SslStream(network, false, validate)) {
          var handshake = tls.AuthenticateAsClientAsync(serverName, null, SslProtocols.Tls12, false);
          if (!handshake.Wait(timeoutMs)) { result.code = "RELAY_TIMEOUT"; return result; }
          if (!tls.IsAuthenticated || !tls.IsEncrypted) return result;
          result.success = true; result.code = "RELAY_TLS_VERIFIED";
        }
      } catch (Exception error) {
        while (error.InnerException != null) error = error.InnerException;
        result.exceptionType = error.GetType().Name;
        if (certificateRejected) result.code = "RELAY_CERTIFICATE_REJECTED";
      } finally {
        if (client != null) client.Close();
        result.elapsedMs = watch.ElapsedMilliseconds;
      }
      return result;
    }

    public static Result Https(string url, int proxyPort, bool systemRoute, string method, int timeoutMs) {
      Result result = new Result { code = "CHAIN_REQUEST_FAILED" };
      Stopwatch watch = Stopwatch.StartNew();
      HttpWebRequest request = null;
      HttpWebResponse response = null;
      try {
        Uri target = new Uri(url);
        if (target.Scheme != "https" || !String.IsNullOrEmpty(target.UserInfo) || (method != "GET" && method != "HEAD")) return result;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        request = (HttpWebRequest)WebRequest.Create(target);
        request.Proxy = systemRoute ? null : new WebProxy("http://127.0.0.1:" + proxyPort.ToString(), false);
        request.AllowAutoRedirect = false; request.UseDefaultCredentials = false;
        request.PreAuthenticate = false; request.KeepAlive = false;
        request.Method = method; request.Timeout = timeoutMs; request.ReadWriteTimeout = timeoutMs;
        request.UserAgent = "MC-Proxy-Offline-Diagnostics/1";
        request.AutomaticDecompression = DecompressionMethods.None;
        try { response = (HttpWebResponse)request.GetResponse(); }
        catch (WebException error) {
          response = error.Response as HttpWebResponse;
          if (response == null) {
            if (error.Status == WebExceptionStatus.Timeout) result.code = "CHAIN_TIMEOUT";
            else if (error.Status == WebExceptionStatus.TrustFailure || error.Status == WebExceptionStatus.SecureChannelFailure) result.code = "TARGET_TLS_REJECTED";
            else if (error.Status == WebExceptionStatus.ConnectFailure) result.code = systemRoute ? "SYSTEM_ROUTE_UNREACHABLE" : "LOCAL_PROXY_UNREACHABLE";
            else if (error.Status == WebExceptionStatus.NameResolutionFailure) result.code = "DNS_RESOLUTION_FAILED";
            return result;
          }
        }
        result.statusCode = (int)response.StatusCode;
        result.success = true; result.code = "HTTPS_REACHED";
        if (method == "GET" && result.statusCode == 200) {
          using (Stream stream = response.GetResponseStream())
          using (MemoryStream memory = new MemoryStream()) {
            byte[] buffer = new byte[1024]; int count;
            while ((count = stream.Read(buffer, 0, buffer.Length)) > 0) {
              if (memory.Length + count > 16384) { result.success = false; result.code = "RESPONSE_TOO_LARGE"; return result; }
              memory.Write(buffer, 0, count);
              if (watch.ElapsedMilliseconds > timeoutMs) { result.success = false; result.code = "CHAIN_TIMEOUT"; return result; }
            }
            result.body = System.Text.Encoding.UTF8.GetString(memory.ToArray());
          }
        }
      } catch (Exception) { result.success = false; }
      finally {
        if (response != null) response.Close();
        if (request != null) request.Abort();
        result.elapsedMs = watch.ElapsedMilliseconds;
      }
      return result;
    }
  }
}
