// Offline verification for the Python Spawns engine — run via
// docs/py-spawns-selftest.sh (which drives the TLS half with real python
// traffic over a local relay). No elevation needed.
//
//   reassemble                    synthetic IP/TCP packets → reassembled streams
//   tls <client.bin> <server.bin> <keylog-dir>   real captured TLS streams → plaintext

using System.Net;
using System.Threading;
using System.Text;
using LookSee.Models;
using LookSee.Services;

namespace PyTraceSelfTest
{
    internal static class Program
    {
        // -----------------------------------------------------------------------
        // TLS 1.2 parameter sweep (debug): find the exact derivation the
        // captured OpenSSL session used, by trying the plausible variants for
        // one post-CCS application_data record.
        // -----------------------------------------------------------------------

        private static int DebugSweep12(string[] args)
        {
            if (args.Length < 4)
            {
                Console.WriteLine("sweep12 <client.bin> <server.bin> <keylog-dir>");
                return 2;
            }
            TlsKeylogService.DirOverride = args[3];
            var keylog = new TlsKeylogService();
            keylog.Refresh();

            byte[] client = File.ReadAllBytes(args[1]);
            byte[] server = File.ReadAllBytes(args[2]);

            // ClientHello random + ServerHello random
            byte[] clientRandom = ParseRandom(client, handshakeType: 1);
            byte[] serverRandom = ParseRandom(server, handshakeType: 2);
            var secrets = keylog.GetSecrets(clientRandom);
            if (secrets == null || !secrets.TryGetValue("CLIENT_RANDOM", out var master))
            {
                Console.WriteLine("no CLIENT_RANDOM secret");
                return 1;
            }

            // The first post-CCS type-23 record in each direction
            var (clientApp, clientSeqAll) = FindAppRecord(client);
            var (serverApp, serverSeqAll) = FindAppRecord(server);
            Console.WriteLine($"client app record: {clientApp.Length} B (record #{clientSeqAll}), server app record: {serverApp.Length} B (record #{serverSeqAll})");

            var hashes = new[] { System.Security.Cryptography.HashAlgorithmName.SHA256,
                                 System.Security.Cryptography.HashAlgorithmName.SHA384 };
            var seeds = new (string name, byte[] seed)[]
            {
                ("srv||cli", serverRandom.Concat(clientRandom).ToArray()),
                ("cli||srv", clientRandom.Concat(serverRandom).ToArray()),
            };

            int found = 0;
            foreach (var hash in hashes)
            foreach (var (seedName, seed) in seeds)
            foreach (int keyLen in new[] { 16, 32 })
            {
                int blockLen = keyLen * 2 + 4 * 2;
                byte[] block = Prf(master, "key expansion", seed, blockLen, hash);
                // RFC 5246 §6.3 grouped layout: [client key][server key][client IV][server IV]
                byte[] clientKey = block[..keyLen];
                byte[] serverKey = block[keyLen..(keyLen * 2)];
                byte[] clientIv = block[(keyLen * 2)..(keyLen * 2 + 4)];
                byte[] serverIv = block[(keyLen * 2 + 4)..];

                foreach (var (dir, data, halfKey, halfIv, seqAll) in new[]
                     {
                         ("client", clientApp, clientKey, clientIv, clientSeqAll),
                         ("client", clientApp, serverKey, serverIv, clientSeqAll), // crossed halves
                         ("server", serverApp, serverKey, serverIv, serverSeqAll),
                         ("server", serverApp, clientKey, clientIv, serverSeqAll)  // crossed halves
                     })
                foreach (long aadSeq in new long[] { 0, 1, 2, 3, seqAll })
                foreach (string lenMode in new[] { "plain", "ct", "full" })
                foreach (bool ivAfter in new[] { false, true }) // fixed||explicit vs explicit||fixed
                {
                    if (data.Length < 8 + 16) continue;
                    int lenValue = lenMode switch
                    {
                        "plain" => data.Length - 8 - 16,
                        "ct" => data.Length - 8,
                        _ => data.Length
                    };
                    var nonce = new byte[12];
                    if (ivAfter)
                    {
                        Array.Copy(data, 0, nonce, 0, 8);
                        Array.Copy(halfIv, 0, nonce, 8, 4);
                    }
                    else
                    {
                        Array.Copy(halfIv, 0, nonce, 0, 4);
                        Array.Copy(data, 0, nonce, 4, 8);
                    }
                    var aad = new byte[13];
                    for (int i = 0; i < 8; i++) aad[i] = (byte)(aadSeq >> (8 * (7 - i)));
                    aad[8] = 23; aad[9] = 0x03; aad[10] = 0x03;
                    aad[11] = (byte)(lenValue >> 8); aad[12] = (byte)(lenValue & 0xFF);

                    if (TryGcm(halfKey, nonce, data[8..], aad, out byte[] plain))
                    {
                        Console.WriteLine($"HIT dir={dir} hash={hash.Name} seed={seedName} keyLen={keyLen} aadSeq={aadSeq} len={lenMode}");
                        Console.WriteLine($"    plaintext[{plain.Length}]: {Encoding.ASCII.GetString(plain.Take(60).ToArray()).Replace("\r", "\\r").Replace("\n", "\\n")}");
                        found++;
                    }
                }
            }
            Console.WriteLine(found > 0 ? $"SWEEP: {found} variant(s) decrypt" : "SWEEP: nothing decrypts — derivation is outside the matrix");
            return found > 0 ? 0 : 1;
        }

        private static byte[] Prf(byte[] secret, string label, byte[] seed, int length,
            System.Security.Cryptography.HashAlgorithmName hash)
        {
            byte[] labelSeed = Encoding.ASCII.GetBytes(label).Concat(seed).ToArray();
            using System.Security.Cryptography.HMAC hmac = hash == System.Security.Cryptography.HashAlgorithmName.SHA384
                ? new System.Security.Cryptography.HMACSHA384(secret)
                : new System.Security.Cryptography.HMACSHA256(secret);
            byte[] a = hmac.ComputeHash(labelSeed);
            var output = new byte[length];
            int filled = 0;
            while (filled < length)
            {
                byte[] block = hmac.ComputeHash(a.Concat(labelSeed).ToArray());
                int take = Math.Min(block.Length, length - filled);
                Array.Copy(block, 0, output, filled, take);
                filled += take;
                a = hmac.ComputeHash(a);
            }
            return output;
        }

        private static bool TryGcm(byte[] key, byte[] nonce, byte[] ctAndTag, byte[] aad, out byte[] plain)
        {
            plain = null;
            try
            {
                var result = new byte[ctAndTag.Length - 16];
                using var aes = new System.Security.Cryptography.AesGcm(key, 16);
                aes.Decrypt(nonce, ctAndTag[..^16], ctAndTag[^16..], result, aad);
                plain = result;
                return true;
            }
            catch { return false; }
        }

        private static byte[] ParseRandom(byte[] stream, int handshakeType)
        {
            int pos = 0;
            while (pos + 5 <= stream.Length)
            {
                int len = (stream[pos + 3] << 8) | stream[pos + 4];
                if (stream[pos] == 22 && stream[pos + 5] == handshakeType && pos + 5 + 38 <= stream.Length)
                {
                    int hsLen = (stream[pos + 6] << 16) | (stream[pos + 7] << 8) | stream[pos + 8];
                    if (hsLen + 4 >= 36)
                        return stream[(pos + 5 + 4 + 2)..(pos + 5 + 4 + 2 + 32)];
                }
                pos += 5 + len;
            }
            return null;
        }

        private static (byte[] payload, int indexAll) FindAppRecord(byte[] stream)
        {
            int pos = 0, n = 0;
            bool ccs = false;
            while (pos + 5 <= stream.Length)
            {
                int len = (stream[pos + 3] << 8) | stream[pos + 4];
                if (stream[pos] == 20) ccs = true;
                if (stream[pos] == 23 && ccs)
                    return (stream[(pos + 5)..(pos + 5 + len)], n);
                pos += 5 + len;
                n++;
            }
            return (null, -1);
        }

        private static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            if (args.Length == 0)
            {
                Console.WriteLine("usage: reassemble | unblock [dir] | discover [keylog-dir] | sweep12 <client.bin> <server.bin> <keylog-dir> | tls <client.bin> <server.bin> <keylog-dir>");
                return 2;
            }
            return args[0] switch
            {
                "reassemble" => TestReassembly(),
                "sweep12" => DebugSweep12(args),
                "discover" => Discover(args),
                _ => TestTlsDecrypt(args)
            };
        }



        // -----------------------------------------------------------------------
        // Environment discovery (debug): print every python the installer
        // service finds on this machine, tier 1 + a bounded venv scan.
        // -----------------------------------------------------------------------

        private static int Discover(string[] args)
        {
            if (args.Length > 1) TlsKeylogService.DirOverride = args[1];
            var installer = new PyTraceInstallerService();

            Console.WriteLine("=== Tier 1: registry / PATH / Store / conda / uv / pyenv-win / scoop / choco ===");
            var tier1 = installer.DiscoverEnvironments();
            foreach (var env in tier1)
                Console.WriteLine($"  [{env.Source,-12}] {(env.CanInstrument ? "ok  " : "NO  ")} {env.Root}  ->  {env.SitePackages}");

            Console.WriteLine();
            Console.WriteLine("=== Tier 2: bounded pyvenv.cfg scan ===");
            var roots = installer.GetScanRoots();
            Console.WriteLine($"  roots: {string.Join(", ", roots)}");
            int found = 0;
            PyTraceInstallerService.ScanForVenvs(roots, maxDepth: 6, maxDirectories: 100_000,
                env =>
                {
                    Interlocked.Increment(ref found);
                    Console.WriteLine($"  [{env.Source}] {env.Root}");
                }, CancellationToken.None);
            Console.WriteLine($"\nDISCOVER: tier1={tier1.Count}, tier2={found}");
            return 0;
        }

        // -----------------------------------------------------------------------
        // TCP reassembly over synthetic packets
        // -----------------------------------------------------------------------

        private static int TestReassembly()
        {
            var capture = new TcpStreamCaptureService { IdleTimeout = TimeSpan.FromSeconds(2) };
            TcpFlowRecord finalized = null;
            capture.OnFlowFinalized += f => finalized = f;

            var clientEp = new IPEndPoint(IPAddress.Parse("192.0.2.10"), 51000);
            var serverEp = new IPEndPoint(IPAddress.Parse("93.184.216.34"), 443);

            // Deterministic payloads
            var clientBytes = new byte[5234];
            var serverBytes = new byte[3000];
            for (int i = 0; i < clientBytes.Length; i++) clientBytes[i] = (byte)(i * 7 + 3);
            for (int i = 0; i < serverBytes.Length; i++) serverBytes[i] = (byte)(255 - i * 5);

            const byte syn = 0x02, fin = 0x01, ack = 0x10, psh = 0x08;
            uint clientSeq = 1000, serverSeq = 5000;

            capture.ProcessIpPacket(Packet(clientEp, serverEp, clientSeq, syn | ack, null), FullLen(null));

            // Client data: three segments, the SECOND delivered late (out of
            // order), the third retransmitted once (duplicate), then a
            // retransmit that overlaps the tail of the last segment.
            var seg1 = clientBytes[..2000];
            var seg2 = clientBytes[2000..4000];
            var seg3 = clientBytes[4000..];

            capture.ProcessIpPacket(Packet(clientEp, serverEp, clientSeq + 1, psh | ack, seg1), FullLen(seg1));
            capture.ProcessIpPacket(Packet(clientEp, serverEp, clientSeq + 1 + 4000, psh | ack, seg3), FullLen(seg3)); // ahead of order
            capture.ProcessIpPacket(Packet(clientEp, serverEp, clientSeq + 1 + 2000, psh | ack, seg2), FullLen(seg2)); // fills the gap
            capture.ProcessIpPacket(Packet(clientEp, serverEp, clientSeq + 1 + 2000, psh | ack, seg2), FullLen(seg2)); // exact duplicate
            capture.ProcessIpPacket(Packet(clientEp, serverEp, clientSeq + 1 + 4000, psh | ack,
                clientBytes[4500..]), FullLen(clientBytes[4500..])); // partial-overlap retransmit

            // Server data in order + FIN both ways
            capture.ProcessIpPacket(Packet(serverEp, clientEp, serverSeq + 1, psh | ack, serverBytes), FullLen(serverBytes));
            capture.ProcessIpPacket(Packet(clientEp, serverEp, clientSeq + 1 + (uint)clientBytes.Length, fin | ack, null), FullLen(null));
            capture.ProcessIpPacket(Packet(serverEp, clientEp, serverSeq + 1 + (uint)serverBytes.Length, fin | ack, null), FullLen(null));

            if (finalized == null)
            {
                Console.WriteLine("FAIL: flow did not finalize after both FINs.");
                return 1;
            }

            bool ok = true;
            ok &= Check("client stream", clientBytes, finalized.ClientData);
            ok &= Check("server stream", serverBytes, finalized.ServerData);
            ok &= Expect(finalized.ClientEndpoint == "192.0.2.10:51000", "client endpoint attribution (SYN sender)");
            ok &= Expect(finalized.FinBoth, "both FINs recorded");

            Console.WriteLine(ok ? "REASSEMBLE: PASS" : "REASSEMBLE: FAIL");
            return ok ? 0 : 1;
        }

        private static bool Check(string what, byte[] expected, byte[] actual)
        {
            bool equal = actual != null && actual.Length == expected.Length &&
                         expected.AsSpan().SequenceEqual(actual);
            if (!equal)
                Console.WriteLine($"  mismatch in {what}: expected {expected.Length} bytes, got {actual?.Length ?? -1}");
            return equal;
        }

        private static bool Expect(bool condition, string what)
        {
            if (!condition) Console.WriteLine($"  failed: {what}");
            return condition;
        }

        private static int FullLen(byte[] payload) => 20 + 20 + (payload?.Length ?? 0);

        private static byte[] Packet(IPEndPoint src, IPEndPoint dst, uint seq, byte flags, byte[] payload)
        {
            payload ??= Array.Empty<byte>();
            var packet = new byte[20 + 20 + payload.Length];

            // IPv4 header
            packet[0] = 0x45;
            packet[2] = (byte)((packet.Length >> 8) & 0xFF);
            packet[3] = (byte)(packet.Length & 0xFF);
            packet[8] = 64; // TTL
            packet[9] = 6;  // TCP
            src.Address.GetAddressBytes().CopyTo(packet, 12);
            dst.Address.GetAddressBytes().CopyTo(packet, 16);

            // TCP header
            int tcp = 20;
            packet[tcp] = (byte)(src.Port >> 8);
            packet[tcp + 1] = (byte)(src.Port & 0xFF);
            packet[tcp + 2] = (byte)(dst.Port >> 8);
            packet[tcp + 3] = (byte)(dst.Port & 0xFF);
            packet[tcp + 4] = (byte)(seq >> 24);
            packet[tcp + 5] = (byte)(seq >> 16);
            packet[tcp + 6] = (byte)(seq >> 8);
            packet[tcp + 7] = (byte)seq;
            packet[tcp + 12] = 0x50; // data offset 5 (20 bytes)
            packet[tcp + 13] = flags;
            payload.CopyTo(packet, tcp + 20);
            return packet;
        }

        // -----------------------------------------------------------------------
        // TLS decryption of real relayed streams
        // -----------------------------------------------------------------------

        private static int TestTlsDecrypt(string[] args)
        {
            if (args.Length < 4)
            {
                Console.WriteLine("tls mode needs <client.bin> <server.bin> <keylog-dir>");
                return 2;
            }

            TlsKeylogService.DirOverride = args[3];
            var keylog = new TlsKeylogService();
            keylog.Refresh();
            Console.WriteLine($"keylog sessions: {keylog.SessionCount}");

            var flow = new TcpFlowRecord
            {
                Key = "selftest",
                ClientEndpoint = "127.0.0.1:client",
                ServerEndpoint = "relay:443",
                ClientData = File.ReadAllBytes(args[1]),
                ServerData = File.ReadAllBytes(args[2]),
                StartedUtc = DateTime.UtcNow.AddMinutes(-1),
                EndedUtc = DateTime.UtcNow
            };

            var result = TlsDecryptor.Decrypt(flow, keylog);

            Console.WriteLine($"header : {result.HeaderLine}");
            Console.WriteLine($"status : {result.Status}");
            Console.WriteLine($"app    : {result.ClientAppBytes} bytes up, {result.ServerAppBytes} bytes down");

            bool ok = true;
            ok &= Expect(!string.IsNullOrEmpty(result.Sni), "SNI parsed");
            ok &= Expect(result.Success, "at least one application_data record decrypted");
            ok &= Expect(result.TlsVersion != null, "TLS version identified");

            if (result.HttpSummary != null)
            {
                Console.WriteLine("http summary:");
                Console.WriteLine(result.HttpSummary);
            }
            else
            {
                ok &= Expect(false, "HTTP/1.x summary parsed from plaintext");
            }

            // Show the first decrypted request bytes as evidence
            var firstRequest = result.Records
                .FirstOrDefault(r => r.Decrypted && r.FromClient && r.ContentType == "application_data");
            if (firstRequest != null)
            {
                var text = Encoding.ASCII.GetString(firstRequest.Data.Take(160).ToArray());
                Console.WriteLine($"first request bytes: {text.Replace("\r", "\\r").Replace("\n", "\\n")}");
            }

            Console.WriteLine(ok ? "TLS-DECRYPT: PASS" : "TLS-DECRYPT: FAIL");
            return ok ? 0 : 1;
        }
    }
}
