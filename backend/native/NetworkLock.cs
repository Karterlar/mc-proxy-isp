// Original MC implementation of the documented Windows Filtering Platform API.
// No firewall policy export/import and no objects outside this provider are changed.
// Persistent filters start with BFE; boot-time protection is intentionally not claimed.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.IO.Pipes;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.AccessControl;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

internal static class NetworkLock {
    static readonly Guid ProviderKey = new Guid("a893b10a-88a9-4a46-a4d7-92a5a53b9aa1");
    static readonly Guid SubLayerKey = new Guid("79b51f03-893b-4ede-aad6-89f229861f8d");
    static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid Receive4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), Receive6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
    static readonly Guid Transport4 = new Guid("09e61aea-d214-46e2-9b21-b26b0b2f28c8"), Transport6 = new Guid("e1735bde-013f-4655-b351-a49e15762df0");
    static readonly Guid Resource4 = new Guid("1247d66d-0b60-4a15-8d44-7155d0f53a0c");
    static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"), RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b"), Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    static readonly Guid LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
    static readonly Guid LocalInterface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4"), Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
    static readonly Guid LocalAddress = new Guid("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    const string ServiceName = "MCProxyNetworkLock", Label = "MC Proxy Network Lock v1";
    const string PipeName = "MCProxy.NetworkLock.v1.inspect";
    const uint Persistent = 1, Disabled = 0x20, Block = 0x1001, Permit = 0x1002;
    const uint ProviderNotFound = 0x80320005, SubLayerNotFound = 0x80320007;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 32768, RecursionLimit = 12 };
    static string operation = "inspect";
    static string nativeStage = "input";

    public sealed class Endpoint { public string ip; public int port; public string protocol; }
    public sealed class Dhcp4 { public string luid; public string[] servers; }
    public sealed class Plan { public int version = 1; public string id, binding, corePath, tunLuid; public Endpoint endpoint; public Dhcp4[] dhcp4; }
    public sealed class Request { public string operation { get; set; } public string id { get; set; } public string binding { get; set; } public string corePath { get; set; } public string expectedFingerprint { get; set; } public string tunAlias { get; set; } public Endpoint endpoint { get; set; } public bool includeTun { get; set; } }
    sealed class LockError : Exception { public string Code; public uint? Native; public LockError(string code, uint? native = null) { Code = code; Native = native; } }
    sealed class Rule { public string role; public Guid key, layer; public uint action; public ulong weight; public List<Condition> conditions = new List<Condition>(); }
    sealed class Condition { public Guid key; public uint match, type; public object value; }
    sealed class Observation { public bool present, verified, serviceReady, tunCurrent; public Plan plan; public int ownedFilterCount; public string fingerprint; public List<Guid> keys = new List<Guid>(); }

    [StructLayout(LayoutKind.Sequential)] struct Display { public IntPtr name, description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] struct Value { [FieldOffset(0)] public uint type; [FieldOffset(8)] public byte u8; [FieldOffset(8)] public ushort u16; [FieldOffset(8)] public uint u32; [FieldOffset(8)] public IntPtr pointer; }
    [StructLayout(LayoutKind.Sequential)] struct NativeCondition { public Guid key; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid key; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] struct Context { [FieldOffset(0)] public ulong raw; [FieldOffset(0)] public Guid key; }
    [StructLayout(LayoutKind.Sequential)] struct Filter { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data; public Guid layer, subLayer; public Value weight; public uint count; public IntPtr conditions; public Action action; public Context context; public IntPtr reserved; public ulong id; public Value effectiveWeight; }
    [StructLayout(LayoutKind.Sequential)] struct Provider { public Guid key; public Display display; public uint flags; public Blob data; public IntPtr service; }
    [StructLayout(LayoutKind.Sequential)] struct SubLayer { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data; public ushort weight; }
    [StructLayout(LayoutKind.Sequential)] struct EnumTemplate { public IntPtr provider; public Guid layer; public uint type, flags; public IntPtr providerContext; public uint count; public IntPtr conditions; public uint actionMask; public IntPtr callout; }
    [StructLayout(LayoutKind.Sequential)] struct ServiceConfig { public uint type, startType, errorControl; public IntPtr binaryPath, loadOrder; public uint tag; public IntPtr dependencies, account, display; }
    [StructLayout(LayoutKind.Sequential)] struct ServiceStatus { public uint type, state, controls, win32Exit, serviceExit, checkpoint, waitHint; }
    [StructLayout(LayoutKind.Sequential)] struct ServiceStatusProcess { public uint type, state, controls, win32Exit, serviceExit, checkpoint, waitHint, processId, serviceFlags; }
    [StructLayout(LayoutKind.Sequential)] struct FileInformation { public uint attributes; public System.Runtime.InteropServices.ComTypes.FILETIME creation, access, write; public uint volume, sizeHigh, sizeLow, links, indexHigh, indexLow; }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr authIdentity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderGetByKey0(IntPtr engine, ref Guid key, out IntPtr provider);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderAdd0(IntPtr engine, ref Provider provider, IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr subLayer);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref SubLayer subLayer, IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, ref EnumTemplate template, out IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr handle, uint requested, out IntPtr entries, out uint count);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
    [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)] static extern uint ConvertInterfaceAliasToLuid(string alias, out ulong luid);
    [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateService(IntPtr manager, string name, string display, uint access, uint type, uint start, uint error, string binary, string group, IntPtr tag, string dependencies, string account, string password);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryServiceConfig(IntPtr service, IntPtr config, uint bytes, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatusProcess status, uint bytes, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool StartService(IntPtr service, uint count, IntPtr args);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(IntPtr handle, out FileInformation info);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);

    sealed class Arena : IDisposable {
        readonly List<IntPtr> pointers = new List<IntPtr>();
        public IntPtr Allocate(int bytes) { var p = Marshal.AllocHGlobal(bytes); pointers.Add(p); Marshal.Copy(new byte[bytes], 0, p, bytes); return p; }
        public IntPtr Struct<T>(T value) { var p = Allocate(Marshal.SizeOf(typeof(T))); Marshal.StructureToPtr(value, p, false); return p; }
        public IntPtr String(string text) { var p = Marshal.StringToHGlobalUni(text); pointers.Add(p); return p; }
        public IntPtr Bytes(byte[] bytes) { var p = Allocate(Math.Max(1, bytes.Length)); Marshal.Copy(bytes, 0, p, bytes.Length); return p; }
        public Blob Blob(byte[] bytes) { return new Blob { size = (uint)bytes.Length, data = Bytes(bytes) }; }
        public void Dispose() { for (int i = pointers.Count - 1; i >= 0; i--) Marshal.FreeHGlobal(pointers[i]); }
    }
    static T Read<T>(IntPtr pointer) { return (T)Marshal.PtrToStructure(pointer, typeof(T)); }
    static void Check(uint result, string stage = null) { if (stage != null) nativeStage = stage; if (result != 0) throw new LockError(result == 5 ? "ADMIN_REQUIRED" : "NETWORK_LOCK_WFP_FAILED", result); }
    static void Require(bool condition, string code = "NETWORK_LOCK_INPUT_INVALID") { if (!condition) throw new LockError(code); }
    static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
    static string Hash(string text) { using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(text))); }
    static string Text(IntPtr pointer) { return pointer == IntPtr.Zero ? null : Marshal.PtrToStringUni(pointer); }
    static byte[] Bytes(Blob blob) { Require(blob.size <= 32768 && (blob.size == 0 || blob.data != IntPtr.Zero), "NETWORK_LOCK_RECOVERY_REQUIRED"); var bytes = new byte[blob.size]; if (bytes.Length > 0) Marshal.Copy(blob.data, bytes, 0, bytes.Length); return bytes; }
    static bool Digest(string value) { return value != null && Regex.IsMatch(value, "\\A[0-9a-f]{64}\\z"); }
    static Guid Key(string id, string role) { using (var sha = SHA256.Create()) { var b = sha.ComputeHash(Encoding.UTF8.GetBytes(ProviderKey + ":" + id + ":" + role)).Take(16).ToArray(); return new Guid(b); } }
    static void SafeFile(string file) {
        Require(file != null && file.Length <= 1024 && Path.IsPathRooted(file) && !file.StartsWith("\\\\", StringComparison.Ordinal) && !file.Contains("\"") && !file.Any(char.IsControl));
        string full = Path.GetFullPath(file); Require(String.Equals(full, file, StringComparison.OrdinalIgnoreCase) && Path.GetExtension(full).Equals(".exe", StringComparison.OrdinalIgnoreCase));
        var current = new FileInfo(full); Require(current.Exists && (current.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0);
        for (var parent = current.Directory; parent != null; parent = parent.Parent) Require((parent.Attributes & FileAttributes.ReparsePoint) == 0);
        using (var handle = File.Open(full, FileMode.Open, FileAccess.Read, FileShare.Read)) { FileInformation info; Require(GetFileInformationByHandle(handle.SafeFileHandle.DangerousGetHandle(), out info) && info.links == 1); }
    }
    static void ValidatePlan(Plan p, bool fileCheck) {
        Guid id; Require(p != null && p.version == 1 && Guid.TryParseExact(p.id, "D", out id) && p.id[14] == '4' && "89ab".Contains(p.id[19]) && Digest(p.binding));
        IPAddress ip; Require(p.endpoint != null && IPAddress.TryParse(p.endpoint.ip, out ip) && ip.ToString() == p.endpoint.ip && !ip.IsIPv4MappedToIPv6 && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any) && ip.ScopeIdSafe() == 0);
        Require(p.endpoint.port >= 1 && p.endpoint.port <= 65535 && (p.endpoint.protocol == "TCP" || p.endpoint.protocol == "UDP"));
        ulong luid; Require(p.tunLuid == null || (UInt64.TryParse(p.tunLuid, NumberStyles.None, CultureInfo.InvariantCulture, out luid) && luid > 0 && luid.ToString(CultureInfo.InvariantCulture) == p.tunLuid));
        if (p.dhcp4 != null) { Require(p.dhcp4.Length <= 16 && p.dhcp4.All(d => d != null) && p.dhcp4.Select(d => d.luid).Distinct().Count() == p.dhcp4.Length);
            foreach (var d in p.dhcp4) Require(UInt64.TryParse(d.luid, NumberStyles.None, CultureInfo.InvariantCulture, out luid) && luid > 0 && d.luid == luid.ToString(CultureInfo.InvariantCulture) && d.servers != null && d.servers.Length <= 8 && d.servers.Distinct().Count() == d.servers.Length && d.servers.All(PrivateDhcpAddress)); }
        Require(p.corePath != null && p.corePath.Length <= 1024 && !p.corePath.Any(char.IsControl) && Path.IsPathRooted(p.corePath) && !p.corePath.StartsWith("\\\\", StringComparison.Ordinal) && !p.corePath.Contains("\"") && Path.GetFullPath(p.corePath).Equals(p.corePath, StringComparison.OrdinalIgnoreCase) && Path.GetExtension(p.corePath).Equals(".exe", StringComparison.OrdinalIgnoreCase)); if (fileCheck) SafeFile(p.corePath);
    }
    static long ScopeIdSafe(this IPAddress ip) { return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? ip.ScopeId : 0; }
    static Request ParseRequest(string input) {
        Require(Encoding.UTF8.GetByteCount(input) <= 32768); var map = Json.Deserialize<Dictionary<string, object>>(input); Require(map != null);
        var allowed = new HashSet<string>(new [] { "operation", "id", "binding", "corePath", "endpoint", "includeTun", "tunAlias", "tunLuid", "expectedFingerprint" }); Require(map.Keys.All(allowed.Contains));
        foreach (string key in new [] { "operation", "id", "binding", "corePath", "tunAlias", "expectedFingerprint" }) Require(!map.ContainsKey(key) || map[key] == null || map[key] is string);
        Require(!map.ContainsKey("includeTun") || map["includeTun"] is bool);
        var r = Json.Deserialize<Request>(input); Require(r != null && new [] { "inspect", "apply", "clear", "plan" }.Contains(r.operation)); operation = r.operation;
        Require(!map.ContainsKey("tunLuid") || map["tunLuid"] == null); Require(!r.includeTun || r.tunAlias == "ProxyPilot"); Require(r.tunAlias == null || r.tunAlias == "ProxyPilot");
        if (r.expectedFingerprint != null) Require(Digest(r.expectedFingerprint));
        if (r.operation == "apply" || r.operation == "plan") ValidatePlan(new Plan { id = r.id, binding = r.binding, corePath = r.corePath, endpoint = r.endpoint }, r.operation != "plan");
        if (r.operation == "clear") { Guid id; Require(Guid.TryParseExact(r.id, "D", out id) && Digest(r.expectedFingerprint)); }
        if (r.endpoint != null) { var e = map["endpoint"] as Dictionary<string, object>; Require(e != null && e.Count == 3 && e.Keys.All(k => k == "ip" || k == "port" || k == "protocol") && e["ip"] is string && e["port"] is int && e["protocol"] is string); }
        return r;
    }

    static Condition C(Guid key, uint type, object value, uint match = 0) { return new Condition { key = key, type = type, value = value, match = match }; }
    static Condition Address(Guid key, string address) {
        var bytes = IPAddress.Parse(address).GetAddressBytes();
        return bytes.Length == 4 ? C(key, 3, ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3]) : C(key, 11, bytes);
    }
    static List<Rule> Rules(Plan p, byte[] application, byte[] dhcpApplication = null) {
        var rules = new List<Rule>();
        var layers = new [] { Connect4, Connect6, Receive4, Receive6 };
        for (int i = 0; i < layers.Length; i++) {
            rules.Add(new Rule { role = "block-" + i, key = Key(p.id, "block-" + i), layer = layers[i], action = Block, weight = 1 });
            var loop = new Rule { role = "loopback-" + i, key = Key(p.id, "loopback-" + i), layer = layers[i], action = Permit, weight = 100 };
            loop.conditions.Add(C(Flags, 3, (uint)1, 6)); loop.conditions.Add(C(Protocol, 1, (byte)6)); rules.Add(loop);
        }
        var physical = new Rule { role = "physical", key = Key(p.id, "physical"), layer = IPAddress.Parse(p.endpoint.ip).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? Connect4 : Connect6, action = Permit, weight = 100 };
        physical.conditions.Add(C(AppId, 12, application)); physical.conditions.Add(Address(RemoteAddress, p.endpoint.ip)); physical.conditions.Add(C(RemotePort, 2, (ushort)p.endpoint.port)); physical.conditions.Add(C(Protocol, 1, (byte)(p.endpoint.protocol == "TCP" ? 6 : 17))); rules.Add(physical);
        // sing-tun strict_route can hard-permit its app at ALE. Cross-layer
        // transport guards cannot be bypassed by that ALE permit, and also check
        // packets from already-authorized flows without waiting for ALE reauth.
        var transports = new [] { Transport4, Transport6 };
        for (int i = 0; i < transports.Length; i++) {
            string blockRole = "transport-block-" + i, loopRole = "transport-loopback-" + i;
            rules.Add(new Rule { role = blockRole, key = Key(p.id, blockRole), layer = transports[i], action = Block, weight = 1 });
            var loop = new Rule { role = loopRole, key = Key(p.id, loopRole), layer = transports[i], action = Permit, weight = 100 };
            loop.conditions.Add(C(Flags, 3, (uint)1, 6)); loop.conditions.Add(C(Protocol, 1, (byte)6)); rules.Add(loop);
        }
        var physicalTransport = new Rule { role = "transport-physical", key = Key(p.id, "transport-physical"), layer = physical.layer == Connect4 ? Transport4 : Transport6, action = Permit, weight = 100 };
        physicalTransport.conditions.Add(Address(RemoteAddress, p.endpoint.ip)); physicalTransport.conditions.Add(C(RemotePort, 2, (ushort)p.endpoint.port)); physicalTransport.conditions.Add(C(Protocol, 1, (byte)(p.endpoint.protocol == "TCP" ? 6 : 17))); rules.Add(physicalTransport);
        if (p.tunLuid != null) for (int i = 0; i < 4; i++) for (int dns = 0; dns < 2; dns++) {
            string role = "tun-" + i + "-" + dns; int family = i % 2;
            var rule = new Rule { role = role, key = Key(p.id, role), layer = i < 2 ? layers[family] : transports[family], action = Permit, weight = 100 };
            rule.conditions.Add(C(LocalInterface, 4, UInt64.Parse(p.tunLuid, CultureInfo.InvariantCulture)));
            rule.conditions.Add(Address(LocalAddress, family == 0 ? "172.30.255.1" : "fdfe:dcba:9876::1"));
            rule.conditions.Add(C(Protocol, 1, (byte)(dns == 0 ? 6 : 17))); if (dns == 1) rule.conditions.Add(C(RemotePort, 2, (ushort)53)); rules.Add(rule);
        }
        if (p.dhcp4 != null && p.dhcp4.Length > 0) {
            Require(dhcpApplication != null, "NETWORK_LOCK_VERIFY_FAILED");
            // A distinct resource-assignment layer prevents strict_route's ALE
            // core hard-permit from borrowing a DHCP maintenance exception.
            var deny = new Rule { role = "core-no-dhcp-bind", key = Key(p.id, "core-no-dhcp-bind"), layer = Resource4, action = Block, weight = 100 };
            deny.conditions.Add(C(AppId, 12, application)); deny.conditions.Add(C(Protocol, 1, (byte)17)); deny.conditions.Add(C(LocalPort, 2, (ushort)68)); rules.Add(deny);
            for (int i = 0; i < p.dhcp4.Length; i++) {
                var d = p.dhcp4[i]; string[] targets = new [] { "255.255.255.255" }.Concat(d.servers).ToArray();
                for (int target = 0; target < targets.Length; target++) for (int layer = 0; layer < 2; layer++) {
                    string role = "dhcp4-out-" + i + "-" + target + "-" + layer;
                    var rule = new Rule { role = role, key = Key(p.id, role), layer = layer == 0 ? Connect4 : Transport4, action = Permit, weight = 100 };
                    if (layer == 0) rule.conditions.Add(C(AppId, 12, dhcpApplication));
                    else rule.conditions.Add(C(LocalInterface, 4, UInt64.Parse(d.luid, CultureInfo.InvariantCulture)));
                    rule.conditions.Add(Address(RemoteAddress, targets[target])); rule.conditions.Add(C(Protocol, 1, (byte)17)); rule.conditions.Add(C(LocalPort, 2, (ushort)68)); rule.conditions.Add(C(RemotePort, 2, (ushort)67)); rules.Add(rule);
                }
                for (int server = 0; server < d.servers.Length; server++) {
                    string role = "dhcp4-in-" + i + "-" + server;
                    var rule = new Rule { role = role, key = Key(p.id, role), layer = Receive4, action = Permit, weight = 100 };
                    rule.conditions.Add(C(AppId, 12, dhcpApplication)); rule.conditions.Add(C(LocalInterface, 4, UInt64.Parse(d.luid, CultureInfo.InvariantCulture))); rule.conditions.Add(Address(RemoteAddress, d.servers[server])); rule.conditions.Add(C(Protocol, 1, (byte)17)); rule.conditions.Add(C(LocalPort, 2, (ushort)68)); rule.conditions.Add(C(RemotePort, 2, (ushort)67)); rules.Add(rule);
                }
            }
        }
        Require(rules.Count <= 512, "NETWORK_LOCK_INPUT_INVALID"); return rules;
    }
    static bool PrivateDhcpAddress(string address) {
        IPAddress ip; if (!IPAddress.TryParse(address, out ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ip.ToString() != address) return false;
        var b = ip.GetAddressBytes(); return b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168 || b[0] == 169 && b[1] == 254;
    }
    static Dhcp4[] ReadDhcp4() {
        var result = new List<Dhcp4>();
        foreach (var n in NetworkInterface.GetAllNetworkInterfaces()) {
            if (n.Name == "ProxyPilot" || n.OperationalStatus != OperationalStatus.Up || !n.Supports(NetworkInterfaceComponent.IPv4) || (n.NetworkInterfaceType != NetworkInterfaceType.Ethernet && n.NetworkInterfaceType != NetworkInterfaceType.Wireless80211)) continue;
            var properties = n.GetIPProperties(); if (!properties.GetIPv4Properties().IsDhcpEnabled) continue;
            ulong luid; Check(ConvertInterfaceAliasToLuid(n.Name, out luid)); Require(luid > 0); var servers = properties.DhcpServerAddresses.Select(ip => ip.ToString()).Where(PrivateDhcpAddress).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToArray();
            Require(servers.Length <= 8 && result.Count < 16); result.Add(new Dhcp4 { luid = luid.ToString(CultureInfo.InvariantCulture), servers = servers });
        }
        return result.OrderBy(d => d.luid, StringComparer.Ordinal).ToArray();
    }
    static byte[] DhcpApplication(Plan plan) { return plan.dhcp4 == null || plan.dhcp4.Length == 0 ? null : Application(Path.Combine(Environment.SystemDirectory, "svchost.exe")); }
    static Value NativeValue(Condition c, Arena a) {
        var v = new Value { type = c.type };
        if (c.type == 1) v.u8 = (byte)c.value; else if (c.type == 2) v.u16 = (ushort)c.value; else if (c.type == 3) v.u32 = (uint)c.value;
        else if (c.type == 4) v.pointer = a.Struct((ulong)c.value);
        else if (c.type == 11) v.pointer = a.Bytes((byte[])c.value);
        else if (c.type == 12) v.pointer = a.Struct(a.Blob((byte[])c.value)); else throw new LockError("NETWORK_LOCK_RECOVERY_REQUIRED");
        return v;
    }
    static string ValueText(Value value) {
        switch (value.type) {
            case 0: return "empty";
            case 1: return value.u8.ToString(CultureInfo.InvariantCulture);
            case 2: return value.u16.ToString(CultureInfo.InvariantCulture);
            case 3: return value.u32.ToString(CultureInfo.InvariantCulture);
            case 4: Require(value.pointer != IntPtr.Zero, "NETWORK_LOCK_RECOVERY_REQUIRED"); return unchecked((ulong)Marshal.ReadInt64(value.pointer)).ToString(CultureInfo.InvariantCulture);
            case 11: Require(value.pointer != IntPtr.Zero, "NETWORK_LOCK_RECOVERY_REQUIRED"); var bytes = new byte[16]; Marshal.Copy(value.pointer, bytes, 0, 16); return Hex(bytes);
            case 12: Require(value.pointer != IntPtr.Zero, "NETWORK_LOCK_RECOVERY_REQUIRED"); return Hex(Bytes(Read<Blob>(value.pointer)));
            default: throw new LockError("NETWORK_LOCK_RECOVERY_REQUIRED");
        }
    }
    static string ConditionText(NativeCondition c) { return c.key + ":" + c.match + ":" + c.value.type + ":" + ValueText(c.value); }
    static string FilterText(Filter f) {
        Require(f.count <= 16 && (f.count == 0 || f.conditions != IntPtr.Zero), "NETWORK_LOCK_RECOVERY_REQUIRED"); var conditions = new List<string>();
        for (uint i = 0; i < f.count; i++) conditions.Add(ConditionText(Read<NativeCondition>(IntPtr.Add(f.conditions, checked((int)i * Marshal.SizeOf(typeof(NativeCondition)))))));
        return String.Join("|", new [] { f.key.ToString(), Text(f.display.name), Text(f.display.description), f.flags.ToString(), f.provider == IntPtr.Zero ? "null" : Read<Guid>(f.provider).ToString(), Hex(Bytes(f.data)), f.layer.ToString(), f.subLayer.ToString(), f.weight.type + ":" + ValueText(f.weight), f.action.type.ToString(), f.action.key.ToString(), (f.flags & 4) != 0 ? f.context.key.ToString() : f.context.raw.ToString(CultureInfo.InvariantCulture), (f.reserved == IntPtr.Zero).ToString(), String.Join(",", conditions.OrderBy(x => x, StringComparer.Ordinal)), f.effectiveWeight.type + ":" + ValueText(f.effectiveWeight) });
    }
    static Filter NativeFilter(Rule r, Arena a) {
        var ptr = a.Allocate(Math.Max(1, r.conditions.Count * Marshal.SizeOf(typeof(NativeCondition))));
        for (int i = 0; i < r.conditions.Count; i++) Marshal.StructureToPtr(new NativeCondition { key = r.conditions[i].key, match = r.conditions[i].match, value = NativeValue(r.conditions[i], a) }, IntPtr.Add(ptr, i * Marshal.SizeOf(typeof(NativeCondition))), false);
        var weight = NativeValue(C(Guid.Empty, 4, r.weight), a);
        return new Filter { key = r.key, display = new Display { name = a.String(Label + ":" + r.role), description = a.String(Label) }, flags = Persistent, provider = a.Struct(ProviderKey), data = a.Blob(Encoding.UTF8.GetBytes(r.role)), layer = r.layer, subLayer = SubLayerKey, weight = weight, count = (uint)r.conditions.Count, conditions = ptr, action = new Action { type = r.action }, effectiveWeight = weight };
    }
    static byte[] Application(string path) {
        IntPtr ptr; Check(FwpmGetAppIdFromFileName0(path, out ptr)); try { return Bytes(Read<Blob>(ptr)); } finally { FwpmFreeMemory0(ref ptr); }
    }
    static string ServiceExecutable() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MC Proxy", "NetworkLock-v1", "MCProxy.NetworkLock.exe"); }
    static string SelfExecutable() { return System.Reflection.Assembly.GetExecutingAssembly().Location; }
    static string FileHash(string file) { using (var stream = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read)) using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(stream)); }
    static void ProtectedDirectory(string directory, bool create) {
        var info = new DirectoryInfo(directory); if (!info.Exists) { Require(create, "NETWORK_LOCK_SERVICE_UNAVAILABLE"); info.Create(); var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false); security.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
            foreach (string sid in new [] { "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545" }) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), sid == "S-1-5-32-545" ? FileSystemRights.ReadAndExecute : FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)); info.SetAccessControl(security); }
        Require((info.Attributes & FileAttributes.ReparsePoint) == 0, "NETWORK_LOCK_SERVICE_UNAVAILABLE");
        var acl = info.GetAccessControl(); string owner = ((SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier))).Value; Require(owner == "S-1-5-18" || owner == "S-1-5-32-544", "NETWORK_LOCK_SERVICE_UNAVAILABLE");
        bool admins = false, system = false;
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) { string sid = ((SecurityIdentifier)rule.IdentityReference).Value;
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (sid == "S-1-5-18") system |= (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl;
            else if (sid == "S-1-5-32-544") admins |= (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl;
            else Require((rule.FileSystemRights & ~(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)) == 0, "NETWORK_LOCK_SERVICE_UNAVAILABLE");
        }
        Require(admins && system && acl.AreAccessRulesProtected, "NETWORK_LOCK_SERVICE_UNAVAILABLE");
        for (var p = info.Parent; p != null; p = p.Parent) Require((p.Attributes & FileAttributes.ReparsePoint) == 0, "NETWORK_LOCK_SERVICE_UNAVAILABLE");
    }
    static void ProtectServiceCopy() {
        string exe = ServiceExecutable(), root = Path.GetDirectoryName(Path.GetDirectoryName(exe)); ProtectedDirectory(root, true); ProtectedDirectory(Path.GetDirectoryName(exe), true); SafeFile(SelfExecutable());
        if (!File.Exists(exe)) { using (var input = File.Open(SelfExecutable(), FileMode.Open, FileAccess.Read, FileShare.Read)) using (var output = new FileStream(exe, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { input.CopyTo(output); output.Flush(true); } var security = File.GetAccessControl(exe); security.SetOwner(new SecurityIdentifier("S-1-5-32-544")); File.SetAccessControl(exe, security); }
        ProtectedFile(exe); Require(FileHash(exe) == FileHash(SelfExecutable()), "NETWORK_LOCK_SERVICE_CONFLICT");
    }
    static void ProtectedFile(string exe) {
        SafeFile(exe); var acl = File.GetAccessControl(exe); string owner = ((SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier))).Value;
        Require(owner == "S-1-5-18" || owner == "S-1-5-32-544", "NETWORK_LOCK_SERVICE_UNAVAILABLE");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) { string sid = ((SecurityIdentifier)rule.IdentityReference).Value;
            if (rule.AccessControlType == AccessControlType.Allow && sid != "S-1-5-18" && sid != "S-1-5-32-544") Require((rule.FileSystemRights & ~(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)) == 0, "NETWORK_LOCK_SERVICE_UNAVAILABLE"); }
    }
    static bool ServiceReady(bool create) {
        // A newer UI may query an older, protected v1 service to recover its lock.
        // Installation/mutation still requires the exact current executable hash.
        string exe = ServiceExecutable(); if (create) ProtectServiceCopy(); else { if (!File.Exists(exe)) return false; ProtectedDirectory(Path.GetDirectoryName(Path.GetDirectoryName(exe)), false); ProtectedDirectory(Path.GetDirectoryName(exe), false); ProtectedFile(exe); }
        IntPtr manager = OpenSCManager(null, null, create ? 3u : 1u); if (manager == IntPtr.Zero) throw new LockError("NETWORK_LOCK_SERVICE_UNAVAILABLE", (uint)Marshal.GetLastWin32Error());
        IntPtr service = IntPtr.Zero;
        try {
            service = OpenService(manager, ServiceName, create ? 0x15u : 5u);
            if (service == IntPtr.Zero) { int code = Marshal.GetLastWin32Error(); if (!create && code == 1060) return false; Require(create && code == 1060, "NETWORK_LOCK_SERVICE_UNAVAILABLE"); service = CreateService(manager, ServiceName, Label, 0x15, 0x10, 2, 1, "\"" + exe + "\" --service", null, IntPtr.Zero, "BFE\0\0", null, null); if (service == IntPtr.Zero) throw new LockError("NETWORK_LOCK_SERVICE_UNAVAILABLE", (uint)Marshal.GetLastWin32Error()); }
            uint needed; QueryServiceConfig(service, IntPtr.Zero, 0, out needed); Require(needed >= Marshal.SizeOf(typeof(ServiceConfig)) && needed <= 16384, "NETWORK_LOCK_SERVICE_UNAVAILABLE");
            using (var a = new Arena()) { var ptr = a.Allocate((int)needed); if (!QueryServiceConfig(service, ptr, needed, out needed)) throw new LockError("NETWORK_LOCK_SERVICE_UNAVAILABLE", (uint)Marshal.GetLastWin32Error()); var config = Read<ServiceConfig>(ptr);
                Require(config.type == 0x10 && config.startType == 2 && config.errorControl == 1 && String.Equals(Text(config.binaryPath), "\"" + exe + "\" --service", StringComparison.OrdinalIgnoreCase) && Text(config.account) == "LocalSystem" && Text(config.dependencies) == "BFE", "NETWORK_LOCK_SERVICE_UNAVAILABLE"); }
            ServiceStatus status; if (!QueryServiceStatus(service, out status)) throw new LockError("NETWORK_LOCK_SERVICE_UNAVAILABLE", (uint)Marshal.GetLastWin32Error());
            if (create && status.state != 4) { if (!StartService(service, 0, IntPtr.Zero) && Marshal.GetLastWin32Error() != 1056) throw new LockError("NETWORK_LOCK_SERVICE_UNAVAILABLE", (uint)Marshal.GetLastWin32Error()); var until = DateTime.UtcNow.AddSeconds(5); do { if (!QueryServiceStatus(service, out status)) throw new LockError("NETWORK_LOCK_SERVICE_UNAVAILABLE", (uint)Marshal.GetLastWin32Error()); if (status.state == 4) break; System.Threading.Thread.Sleep(50); } while (DateTime.UtcNow < until); }
            return status.state == 4;
        } finally { if (service != IntPtr.Zero) CloseServiceHandle(service); CloseServiceHandle(manager); }
    }
    static bool TunCurrent(string expected) {
        if (expected == null) return false;
        ulong luid; uint index; if (ConvertInterfaceAliasToLuid("ProxyPilot", out luid) != 0 || luid.ToString(CultureInfo.InvariantCulture) != expected || ConvertInterfaceLuidToIndex(ref luid, out index) != 0) return false;
        var interfaces = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.Name == "ProxyPilot").ToArray(); if (interfaces.Length != 1 || interfaces[0].OperationalStatus != OperationalStatus.Up) return false;
        var properties = interfaces[0].GetIPProperties(); if ((uint)properties.GetIPv4Properties().Index != index || (uint)properties.GetIPv6Properties().Index != index) return false;
        var addresses = properties.UnicastAddresses.Select(a => a.Address.ToString()).ToArray(); return addresses.Contains("172.30.255.1") && addresses.Contains("fdfe:dcba:9876::1");
    }

    static List<Filter> Enumerate(IntPtr engine, Arena arena) {
        var template = new EnumTemplate { provider = arena.Struct(ProviderKey), flags = 0x18, actionMask = UInt32.MaxValue };
        IntPtr handle; Check(FwpmFilterCreateEnumHandle0(engine, ref template, out handle), "filter-enum-create"); var result = new List<Filter>();
        try { while (true) { IntPtr entries; uint count; Check(FwpmFilterEnum0(engine, handle, 64, out entries, out count));
                try { Require(count <= 64 && result.Count + count <= 512, "NETWORK_LOCK_RECOVERY_REQUIRED"); for (int i = 0; i < count; i++) {
                        Filter f = Read<Filter>(Marshal.ReadIntPtr(entries, i * IntPtr.Size));
                        // Enumeration buffers are freed after processing: clone pointer-backed fields.
                        f.display.name = arena.String(Text(f.display.name) ?? ""); f.display.description = arena.String(Text(f.display.description) ?? "");
                        Require(f.provider != IntPtr.Zero && Read<Guid>(f.provider) == ProviderKey, "NETWORK_LOCK_RECOVERY_REQUIRED"); f.provider = arena.Struct(ProviderKey); f.data = arena.Blob(Bytes(f.data));
                        f.weight = CloneValue(f.weight, arena); f.effectiveWeight = CloneValue(f.effectiveWeight, arena);
                        Require(f.count <= 16 && (f.count == 0 || f.conditions != IntPtr.Zero), "NETWORK_LOCK_RECOVERY_REQUIRED"); var copy = arena.Allocate(Math.Max(1, (int)f.count * Marshal.SizeOf(typeof(NativeCondition))));
                        for (int c = 0; c < f.count; c++) { var condition = Read<NativeCondition>(IntPtr.Add(f.conditions, c * Marshal.SizeOf(typeof(NativeCondition)))); condition.value = CloneValue(condition.value, arena); Marshal.StructureToPtr(condition, IntPtr.Add(copy, c * Marshal.SizeOf(typeof(NativeCondition))), false); }
                        f.conditions = copy; result.Add(f);
                    } } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                if (count == 0) return result;
            } } finally { FwpmFilterDestroyEnumHandle0(engine, handle); }
    }
    static Value CloneValue(Value value, Arena a) {
        switch (value.type) {
            case 0: case 1: case 2: case 3: return value;
            case 4: return NativeValue(C(Guid.Empty, 4, unchecked((ulong)Marshal.ReadInt64(value.pointer))), a);
            case 11: var bytes = new byte[16]; Marshal.Copy(value.pointer, bytes, 0, bytes.Length); return NativeValue(C(Guid.Empty, 11, bytes), a);
            case 12: return NativeValue(C(Guid.Empty, 12, Bytes(Read<Blob>(value.pointer))), a);
            default: throw new LockError("NETWORK_LOCK_RECOVERY_REQUIRED");
        }
    }
    static Observation InspectInside(IntPtr engine, bool checkService) {
        using (var a = new Arena()) {
            var filters = Enumerate(engine, a); Guid pk = ProviderKey, sk = SubLayerKey; IntPtr pp, sp; uint pr = FwpmProviderGetByKey0(engine, ref pk, out pp), sr = FwpmSubLayerGetByKey0(engine, ref sk, out sp);
            var observed = new Observation { present = pr == 0 || sr == 0 || filters.Count > 0, ownedFilterCount = filters.Count, keys = filters.Select(f => f.key).ToList() };
            try {
                if (pr != 0 && pr != ProviderNotFound) Check(pr); if (sr != 0 && sr != SubLayerNotFound) Check(sr);
                if (!observed.present) { observed.verified = true; return observed; }
                if (pr != 0 || sr != 0) return observed;
                Provider provider = Read<Provider>(pp); SubLayer subLayer = Read<SubLayer>(sp);
                byte[] data = Bytes(provider.data); Plan plan;
                try { plan = Json.Deserialize<Plan>(new UTF8Encoding(false, true).GetString(data)); ValidatePlan(plan, false); } catch { return observed; }
                observed.plan = plan;
                string providerText = String.Join("|", new [] { provider.key.ToString(), Text(provider.display.name), Text(provider.display.description), provider.flags.ToString(), Hex(data), Text(provider.service) });
                string subText = String.Join("|", new [] { subLayer.key.ToString(), Text(subLayer.display.name), Text(subLayer.display.description), subLayer.flags.ToString(), subLayer.provider == IntPtr.Zero ? "null" : Read<Guid>(subLayer.provider).ToString(), Hex(Bytes(subLayer.data)), subLayer.weight.ToString() });
                var actual = filters.Select(FilterText).OrderBy(x => x, StringComparer.Ordinal).ToArray(); observed.fingerprint = Hash(providerText + "\n" + subText + "\n" + String.Join("\n", actual));
                bool owners = provider.key == ProviderKey && provider.flags == Persistent && Text(provider.display.name) == Label && Text(provider.display.description) == Label && Text(provider.service) == ServiceName
                    && subLayer.key == SubLayerKey && subLayer.flags == Persistent && subLayer.provider != IntPtr.Zero && Read<Guid>(subLayer.provider) == ProviderKey && subLayer.weight == UInt16.MaxValue && Text(subLayer.display.name) == Label && Text(subLayer.display.description) == Label && Bytes(subLayer.data).SequenceEqual(Encoding.UTF8.GetBytes("MC-WFP-1"));
                if (!owners || filters.Any(f => (f.flags & Disabled) != 0 || f.subLayer != SubLayerKey)) return observed;
                string[] expected;
                try { SafeFile(plan.corePath); expected = Rules(plan, Application(plan.corePath), DhcpApplication(plan)).Select(r => FilterText(NativeFilter(r, a))).OrderBy(x => x, StringComparer.Ordinal).ToArray(); }
                catch { return observed; } // Deleted/upgraded core must not make owned filters impossible to clear.
                if (!actual.SequenceEqual(expected)) return observed;
                try { observed.serviceReady = !checkService || ServiceReady(false); } catch { observed.serviceReady = false; }
                observed.verified = observed.serviceReady;
                if (plan.tunLuid != null) { try { observed.tunCurrent = TunCurrent(plan.tunLuid); } catch { observed.tunCurrent = false; } }
                return observed;
            } finally { if (pp != IntPtr.Zero) FwpmFreeMemory0(ref pp); if (sp != IntPtr.Zero) FwpmFreeMemory0(ref sp); }
        }
    }
    static object Public(Observation o) {
        return new { present = o.present, verified = o.verified, id = o.plan == null ? null : o.plan.id, binding = o.plan == null ? null : o.plan.binding, corePath = o.plan == null ? null : o.plan.corePath, endpoint = o.plan == null ? null : o.plan.endpoint, tunLuid = o.plan == null ? null : o.plan.tunLuid, tunCurrent = o.tunCurrent, ownedFilterCount = o.ownedFilterCount, fingerprint = o.fingerprint, serviceReady = o.serviceReady, bootProtected = false };
    }
    static Observation ReadAbsent(IntPtr engine) {
        // A referenced provider/sublayer cannot be deleted while filters remain.
        // For a non-elevated first run, two successful NOT_FOUND reads prove absence;
        // any present/inaccessible object requires the trusted service snapshot.
        Guid pk = ProviderKey, sk = SubLayerKey; IntPtr pp, sp; uint pr = FwpmProviderGetByKey0(engine, ref pk, out pp), sr = FwpmSubLayerGetByKey0(engine, ref sk, out sp);
        try { if (pr == ProviderNotFound && sr == SubLayerNotFound) return new Observation { present = false, verified = true }; throw new LockError("ADMIN_REQUIRED", pr != ProviderNotFound && pr != 0 ? pr : sr != SubLayerNotFound && sr != 0 ? sr : 5u); }
        finally { if (pp != IntPtr.Zero) FwpmFreeMemory0(ref pp); if (sp != IntPtr.Zero) FwpmFreeMemory0(ref sp); }
    }
    static object ServiceInspect() {
        Require(ServiceReady(false), "NETWORK_LOCK_SERVICE_UNAVAILABLE"); IntPtr scm = OpenSCManager(null, null, 1); if (scm == IntPtr.Zero) throw new LockError("NETWORK_LOCK_SERVICE_UNAVAILABLE"); IntPtr svc = IntPtr.Zero; uint expected;
        try { svc = OpenService(scm, ServiceName, 4); Require(svc != IntPtr.Zero, "NETWORK_LOCK_SERVICE_UNAVAILABLE"); ServiceStatusProcess status; uint needed;
            Require(QueryServiceStatusEx(svc, 0, out status, (uint)Marshal.SizeOf(typeof(ServiceStatusProcess)), out needed) && status.state == 4 && status.processId != 0, "NETWORK_LOCK_SERVICE_UNAVAILABLE"); expected = status.processId;
            using (var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous)) {
                client.Connect(1500); uint actual; Require(GetNamedPipeServerProcessId(client.SafePipeHandle.DangerousGetHandle(), out actual) && actual == expected, "NETWORK_LOCK_SERVICE_CONFLICT");
                byte[] request = Encoding.UTF8.GetBytes("{\"operation\":\"inspect\"}\n"); client.Write(request, 0, request.Length); client.Flush();
                var task = System.Threading.Tasks.Task.Run(() => ReadLine(client, 32768)); Require(task.Wait(6000), "NETWORK_LOCK_SERVICE_UNAVAILABLE"); string response = task.Result;
                Require(QueryServiceStatusEx(svc, 0, out status, (uint)Marshal.SizeOf(typeof(ServiceStatusProcess)), out needed) && status.state == 4 && status.processId == expected && GetNamedPipeServerProcessId(client.SafePipeHandle.DangerousGetHandle(), out actual) && actual == expected, "NETWORK_LOCK_SERVICE_CONFLICT");
                var map = Json.Deserialize<Dictionary<string, object>>(response); Require(map != null && map.ContainsKey("ok") && map["ok"] is bool && (bool)map["ok"] && map.ContainsKey("value"), "NETWORK_LOCK_SERVICE_UNAVAILABLE"); return map["value"];
            }
        } finally { if (svc != IntPtr.Zero) CloseServiceHandle(svc); CloseServiceHandle(scm); }
    }
    static string ReadLine(Stream stream, int max) { var bytes = new List<byte>(); int b; while ((b = stream.ReadByte()) >= 0 && b != 10) { Require(bytes.Count < max); bytes.Add((byte)b); } Require(b == 10); return new UTF8Encoding(false, true).GetString(bytes.ToArray()); }
    static void Remove(IntPtr engine, Observation current) {
        foreach (Guid original in current.keys) { Guid key = original; Check(FwpmFilterDeleteByKey0(engine, ref key)); }
        Guid sk = SubLayerKey, pk = ProviderKey; Check(FwpmSubLayerDeleteByKey0(engine, ref sk)); Check(FwpmProviderDeleteByKey0(engine, ref pk));
    }
    static void Add(IntPtr engine, Plan plan, byte[] application) {
        using (var a = new Arena()) {
            var display = new Display { name = a.String(Label), description = a.String(Label) };
            var provider = new Provider { key = ProviderKey, display = display, flags = Persistent, data = a.Blob(Encoding.UTF8.GetBytes(Json.Serialize(plan))), service = a.String(ServiceName) }; Check(FwpmProviderAdd0(engine, ref provider, IntPtr.Zero));
            var layer = new SubLayer { key = SubLayerKey, display = display, flags = Persistent, provider = a.Struct(ProviderKey), data = a.Blob(Encoding.UTF8.GetBytes("MC-WFP-1")), weight = UInt16.MaxValue }; Check(FwpmSubLayerAdd0(engine, ref layer, IntPtr.Zero));
            foreach (Rule rule in Rules(plan, application, DhcpApplication(plan))) { var filter = NativeFilter(rule, a); ulong id; Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id)); }
        }
    }
    static object Execute(Request r) {
        if (r.operation == "plan") { var plan = new Plan { id = r.id, binding = r.binding, corePath = r.corePath, endpoint = r.endpoint, tunLuid = r.includeTun ? "1" : null }; var rules = Rules(plan, new byte[] { 1 }); return new { ownedFilterCount = rules.Count, roles = rules.Select(x => x.role).ToArray(), bootProtected = false, mutationCalls = 0 }; }
        bool mutation = r.operation != "inspect";
        if (mutation) Require(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator), "ADMIN_REQUIRED");
        Plan next = null; byte[] application = null;
        if (r.operation == "apply") {
            string luid = null; if (r.includeTun) { ulong value; if (ConvertInterfaceAliasToLuid("ProxyPilot", out value) != 0 || value == 0) throw new LockError("NETWORK_LOCK_TUN_UNAVAILABLE"); luid = value.ToString(CultureInfo.InvariantCulture); Require(TunCurrent(luid), "NETWORK_LOCK_TUN_UNAVAILABLE"); }
            next = new Plan { id = r.id, binding = r.binding, corePath = r.corePath, endpoint = r.endpoint, tunLuid = luid, dhcp4 = ReadDhcp4() }; ValidatePlan(next, true); application = Application(next.corePath); Rules(next, application, DhcpApplication(next));
            Require(ServiceReady(true), "NETWORK_LOCK_SERVICE_UNAVAILABLE");
        }
        IntPtr engine; Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine), "engine-open"); bool transaction = false;
        try {
            uint began = FwpmTransactionBegin0(engine, mutation ? 0u : 1u); nativeStage = "transaction-begin";
            if (!mutation && began == 5) { try { return Public(ReadAbsent(engine)); } catch (LockError cause) { if (cause.Code != "ADMIN_REQUIRED") throw; return ServiceInspect(); } }
            Check(began); transaction = true; var current = InspectInside(engine, true);
            if (r.operation == "inspect") { Check(FwpmTransactionCommit0(engine)); transaction = false; return Public(current); }
            if (r.operation == "clear") {
                if (!current.present) { Check(FwpmTransactionCommit0(engine)); transaction = false; return Public(current); }
                Require(current.plan != null && current.plan.id == r.id && current.fingerprint == r.expectedFingerprint, "NETWORK_LOCK_CONFLICT"); Remove(engine, current);
            } else {
                if (current.present) {
                    Require(current.verified && current.plan != null && current.fingerprint == r.expectedFingerprint && current.plan.id == next.id && current.plan.binding == next.binding && String.Equals(current.plan.corePath, next.corePath, StringComparison.OrdinalIgnoreCase) && Json.Serialize(current.plan.endpoint) == Json.Serialize(next.endpoint), "NETWORK_LOCK_CONFLICT");
                    if (current.plan.tunLuid == next.tunLuid && Json.Serialize(current.plan.dhcp4) == Json.Serialize(next.dhcp4)) { Check(FwpmTransactionCommit0(engine)); transaction = false; return Public(current); }
                    Remove(engine, current);
                } else Require(r.expectedFingerprint == null, "NETWORK_LOCK_CONFLICT");
                Add(engine, next, application);
                // Abort instead of committing if native read-back disagrees with even one condition.
                Require(InspectInside(engine, true).verified, "NETWORK_LOCK_VERIFY_FAILED");
            }
            Check(FwpmTransactionCommit0(engine)); transaction = false;
            Check(FwpmTransactionBegin0(engine, 1)); transaction = true; var final = InspectInside(engine, true); Check(FwpmTransactionCommit0(engine)); transaction = false; return Public(final);
        } finally { if (transaction) FwpmTransactionAbort0(engine); FwpmEngineClose0(engine); }
    }
    sealed class LockService : ServiceBase {
        volatile bool stopping; NamedPipeServerStream pipe; System.Threading.Thread worker;
        public LockService() { ServiceName = NetworkLock.ServiceName; CanStop = true; AutoLog = false; }
        NamedPipeServerStream CreatePipe() {
            var security = new PipeSecurity(); security.SetAccessRuleProtection(true, false);
            foreach (string sid in new [] { "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545" }) security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid), sid == "S-1-5-32-545" ? PipeAccessRights.ReadWrite : PipeAccessRights.FullControl, AccessControlType.Allow));
            return new NamedPipeServerStream(PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 32768, 1024, security);
        }
        protected override void OnStart(string[] args) { pipe = CreatePipe(); worker = new System.Threading.Thread(Listen) { IsBackground = true }; worker.Start(); }
        void Listen() {
            while (!stopping) {
                var current = pipe;
                try { current.WaitForConnection();
                    var read = System.Threading.Tasks.Task.Run(() => ReadLine(current, 1024)); Require(read.Wait(1500), "NETWORK_LOCK_SERVICE_UNAVAILABLE");
                    Require(read.Result.Trim() == "{\"operation\":\"inspect\"}"); var request = new Request { operation = "inspect" };
                    string response = Json.Serialize(new { ok = true, value = Execute(request) }) + "\n"; byte[] bytes = Encoding.UTF8.GetBytes(response); var write = current.WriteAsync(bytes, 0, bytes.Length); Require(write.Wait(1500), "NETWORK_LOCK_SERVICE_UNAVAILABLE");
                } catch { } finally { current.Dispose(); }
                if (!stopping) { try { pipe = CreatePipe(); } catch { stopping = true; try { Stop(); } catch { } } }
            }
        }
        protected override void OnStop() { stopping = true; if (pipe != null) pipe.Dispose(); if (worker != null && worker != System.Threading.Thread.CurrentThread) worker.Join(2000); }
    }
    static object SelfTest() {
        Require(IntPtr.Size == 8, "NETWORK_LOCK_WFP_LAYOUT_INVALID");
        var sizes = new Dictionary<string, int> { { "Value", Marshal.SizeOf(typeof(Value)) }, { "Condition", Marshal.SizeOf(typeof(NativeCondition)) }, { "Filter", Marshal.SizeOf(typeof(Filter)) }, { "Provider", Marshal.SizeOf(typeof(Provider)) }, { "SubLayer", Marshal.SizeOf(typeof(SubLayer)) }, { "EnumTemplate", Marshal.SizeOf(typeof(EnumTemplate)) }, { "ServiceConfig", Marshal.SizeOf(typeof(ServiceConfig)) } };
        Require(sizes["Value"] == 16 && sizes["Condition"] == 40 && sizes["Filter"] == 200 && sizes["Provider"] == 64 && sizes["SubLayer"] == 72 && sizes["EnumTemplate"] == 72 && sizes["ServiceConfig"] == 64, "NETWORK_LOCK_WFP_LAYOUT_INVALID");
        Require(Marshal.OffsetOf(typeof(Filter), "conditions").ToInt32() == 120 && Marshal.OffsetOf(typeof(Filter), "context").ToInt32() == 152 && Marshal.OffsetOf(typeof(Filter), "effectiveWeight").ToInt32() == 184, "NETWORK_LOCK_WFP_LAYOUT_INVALID");
        var plan = new Plan { id = "11111111-2222-4333-8444-555555555555", binding = new string('a', 64), corePath = "C:\\fixture\\core.exe", endpoint = new Endpoint { ip = "203.0.113.1", port = 443, protocol = "TCP" } };
        int basic = Rules(plan, new byte[] { 1, 2 }).Count; plan.tunLuid = "123"; var rules = Rules(plan, new byte[] { 1, 2 }); Require(basic == 14 && rules.Count == 22 && rules.Count(x => x.action == Block) == 6);
        Require(rules.Select(r => r.key).Distinct().Count() == rules.Count);
        Require((uint)Address(RemoteAddress, "203.0.113.1").value == 0xcb007101 && (uint)Address(LocalAddress, "172.30.255.1").value == 0xac1eff01);
        Require(((byte[])Address(LocalAddress, "fdfe:dcba:9876::1").value).SequenceEqual(IPAddress.Parse("fdfe:dcba:9876::1").GetAddressBytes()));
        Require(rules.Where(r => r.layer == Transport4 || r.layer == Transport6).All(r => r.conditions.All(c => c.key != AppId)));
        Require(rules.Where(r => r.role.StartsWith("tun-", StringComparison.Ordinal)).All(r => r.conditions.Any(c => c.key == LocalInterface) && r.conditions.Any(c => c.key == LocalAddress)));
        Require(rules.Where(r => r.role.EndsWith("-1", StringComparison.Ordinal) && r.role.StartsWith("tun-", StringComparison.Ordinal)).All(r => r.conditions.Any(c => c.key == RemotePort && (ushort)c.value == 53)));
        using (var a = new Arena()) { foreach (var rule in rules) { var f = NativeFilter(rule, a); Require(f.flags == Persistent && (f.flags & 8) == 0 && f.subLayer == SubLayerKey); string text = FilterText(f); Require(text.Length > 50); } }
        int tunCount = rules.Count; plan.dhcp4 = new [] { new Dhcp4 { luid = "456", servers = new [] { "192.168.1.1" } } }; ValidatePlan(plan, false); var maintained = Rules(plan, new byte[] { 1, 2 }, new byte[] { 3, 4 }); Require(maintained.Count == 28);
        Require(maintained.Any(r => r.layer == Resource4 && r.action == Block && r.conditions.Any(c => c.key == AppId) && r.conditions.Any(c => c.key == LocalPort && (ushort)c.value == 68)));
        Require(maintained.Where(r => r.role.StartsWith("dhcp4-out-", StringComparison.Ordinal) && r.layer == Transport4).All(r => r.conditions.Any(c => c.key == LocalInterface) && r.conditions.Any(c => c.key == RemoteAddress) && r.conditions.Any(c => c.key == LocalPort && (ushort)c.value == 68) && r.conditions.Any(c => c.key == RemotePort && (ushort)c.value == 67)));
        Require(!PrivateDhcpAddress("203.0.113.1") && !PrivateDhcpAddress("127.0.0.1") && !PrivateDhcpAddress("::1"));
        using (var a = new Arena()) {
            var f = NativeFilter(rules.Single(r => r.role == "physical"), a); string original = FilterText(f);
            f.context.key = new Guid("00000000-0000-0000-ffff-ffffffffffff"); Require(FilterText(f) == original); // Inactive union storage is not policy.
            f.flags |= Disabled; Require(FilterText(f) != original);
            f = NativeFilter(rules.Single(r => r.role == "physical"), a); var port = Read<NativeCondition>(IntPtr.Add(f.conditions, 2 * Marshal.SizeOf(typeof(NativeCondition)))); port.value.u16 = 444; Marshal.StructureToPtr(port, IntPtr.Add(f.conditions, 2 * Marshal.SizeOf(typeof(NativeCondition))), false); Require(FilterText(f) != original);
        }
        string valid = Json.Serialize(new Request { operation = "plan", id = plan.id, binding = plan.binding, corePath = plan.corePath, endpoint = plan.endpoint }); Require(ParseRequest(valid).endpoint.port == 443);
        int rejected = 0;
        foreach (string bad in new [] { valid.Replace("\"port\":443", "\"port\":443.5"), valid.Replace("\"includeTun\":false", "\"includeTun\":\"false\""), valid.Insert(valid.Length - 1, ",\"script\":\"ignored\""), valid.Insert(valid.Length - 1, ",\"tunLuid\":\"123\""), valid.Replace("203.0.113.1", "0.0.0.0"), valid.Replace("203.0.113.1", "::ffff:203.0.113.1") }) { try { ParseRequest(bad); } catch { rejected++; } }
        Require(rejected == 6); operation = "inspect";
        return new { selfTest = true, structures = sizes, baselineFilterCount = basic, tunFilterCount = tunCount, dhcpFixtureFilterCount = maintained.Count, invalidInputsRejected = rejected, mutationCalls = 0 };
    }
    public static int Main(string[] args) {
        // SCM services have no console; never attempt console IO in that mode.
        if (args.Length == 1 && args[0] == "--service") { try { ServiceBase.Run(new LockService()); return 0; } catch { return 1; } }
        try {
            Console.InputEncoding = new UTF8Encoding(false, true); Console.OutputEncoding = new UTF8Encoding(false);
            object value;
            if (args.Length == 1 && args[0] == "--self-test") value = SelfTest();
            else { Require(args.Length == 0); var text = new StringBuilder(); int c; while ((c = Console.In.Read()) >= 0) { Require(text.Length < 32768); text.Append((char)c); } value = Execute(ParseRequest(text.ToString())); }
            Console.WriteLine(Json.Serialize(new { ok = true, value = value })); return 0;
        } catch (LockError cause) { Console.WriteLine(Json.Serialize(new { ok = false, code = cause.Code, diagnostic = new { operation = operation, stage = nativeStage, category = cause.Native == 0x80320012 ? "OperationTimeout" : cause.Code == "ADMIN_REQUIRED" ? "PermissionDenied" : cause.Code == "NETWORK_LOCK_CONFLICT" ? "Conflict" : cause.Code.StartsWith("NETWORK_LOCK_SERVICE", StringComparison.Ordinal) ? "ServiceUnavailable" : "WfpFailure", nativeCode = cause.Native } })); return 1; }
        catch { Console.WriteLine(Json.Serialize(new { ok = false, code = "NETWORK_LOCK_WFP_FAILED", diagnostic = new { operation = operation, category = "InvalidData" } })); return 1; }
    }
}
