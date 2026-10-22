using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LookSee.Services
{
    /// <summary>
    /// The block half of AutoCommand's Process Monitor, copied faithfully
    /// into LookSee: the SAME v2 rule scheme, so rules created by either
    /// app are recognized, unblocked and restored by both.
    ///
    /// v2 block rules are FEWER and SELF-DESCRIBING:
    ///   IP:  2 rules (outbound TCP + UDP) — inbound blocks are redundant on
    ///        a client; unsolicited inbound is already dropped by the
    ///        firewall's stateful defaults.
    ///   APP: 1 outbound rule.
    /// Names are deterministic ("AC-BLOCK-IP <ip> (TCP Out)") which makes
    /// creation idempotent and lets wf.msc users sort/filter by "AC-BLOCK".
    /// The Description field carries full provenance (process, PID, host,
    /// byte counts, UTC time) — the audit trail visible in wf.msc.
    /// </summary>
    public class FirewallBlockService
    {
        public static FirewallBlockService Instance => _instance ??= new FirewallBlockService();
        private static FirewallBlockService _instance;

        public const string NewIpPrefix = "AC-BLOCK-IP ";
        public const string NewAppPrefix = "AC-BLOCK-APP ";
        private static readonly string[] LegacyIpPrefix = { "AutoCommand IP Block - " };
        private static readonly string[] LegacyAppPrefix = { "AutoCommand Process Block - " };

        private dynamic GetPolicy()
        {
            Type fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (fwPolicyType == null)
                throw new InvalidOperationException("Windows Firewall COM component not available.");
            return Activator.CreateInstance(fwPolicyType);
        }

        private static dynamic FindRule(dynamic fwPolicy, string name)
        {
            foreach (dynamic r in fwPolicy.Rules)
            {
                try { if ((string)r.Name == name) return r; } catch { }
            }
            return null;
        }

        private static bool IsOurBlock(dynamic rule, out string name)
        {
            name = null;
            try
            {
                name = (string)rule.Name ?? "";
                if ((int)rule.Action != 0) return false; // Block only
                return name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith(NewAppPrefix, StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith(LegacyAppPrefix[0], StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Shared parser: extracts the IP from a v2 or legacy
        /// IP-block rule name. ("AC-BLOCK-IP 1.2.3.4 (TCP Out)" /
        /// "AutoCommand IP Block - 1.2.3.4 (…)")</summary>
        private static string ParseIpTarget(string name)
        {
            string prefix = name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase)
                ? NewIpPrefix : LegacyIpPrefix[0];
            int cut = name.IndexOf('(');
            return (cut > 0 ? name.Substring(prefix.Length, cut - prefix.Length)
                            : name.Substring(prefix.Length)).Trim();
        }

        // ── Create / remove ─────────────────────────────────────────────

        /// <summary>Add a 2-rule (outbound TCP+UDP) idempotent IP block with full provenance.</summary>
        public Task<(int created, int updated)> AddIpBlockAsync(string ip, string description)
        {
            return Task.Run(() =>
            {
                int created = 0, updated = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (var (proto, suffix) in new[] { (6, "TCP Out"), (17, "UDP Out") })
                    {
                        string name = $"{NewIpPrefix}{ip} ({suffix})";
                        dynamic existing = FindRule(fwPolicy, name);
                        if (existing != null)
                        {
                            try { existing.Description = description; updated++; } catch { }
                            continue;
                        }
                        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                        rule.Action = 0; rule.Direction = 2; rule.Enabled = true;
                        rule.InterfaceTypes = "All";
                        rule.Name = name; rule.RemoteAddresses = ip; rule.Protocol = proto;
                        rule.Description = description;
                        fwPolicy.Rules.Add(rule);
                        created++;
                    }
                }
                catch (Exception ex) { throw new Exception($"Failed to add IP block: {ex.Message}", ex); }
                return (created, updated);
            });
        }

        /// <summary>Add a 1-rule (outbound) idempotent app block with full provenance.</summary>
        public Task<(int created, int updated)> AddAppBlockAsync(string appPath, string description)
        {
            return Task.Run(() =>
            {
                int created = 0, updated = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    string name = $"{NewAppPrefix}{System.IO.Path.GetFileName(appPath)} (Out)";
                    dynamic existing = FindRule(fwPolicy, name);
                    if (existing != null)
                    {
                        try { existing.Description = description; updated++; } catch { }
                        return (0, 1);
                    }
                    dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                    rule.Action = 0; rule.Direction = 2; rule.Enabled = true;
                    rule.InterfaceTypes = "All";
                    rule.Name = name; rule.ApplicationName = appPath;
                    rule.Description = description;
                    fwPolicy.Rules.Add(rule);
                    created++;
                }
                catch (Exception ex) { throw new Exception($"Failed to add app block: {ex.Message}", ex); }
                return (created, updated);
            });
        }

        /// <summary>Removes the block rules previously created for a remote
        /// IP (v2 + legacy naming). Returns the removal count.</summary>
        public Task<int> RemoveBlockRulesForIpAsync(string remoteIp)
        {
            return Task.Run(() =>
                RemoveRulesByNamePrefix($"AutoCommand IP Block - {remoteIp} (") +
                RemoveRulesByNamePrefix($"{NewIpPrefix}{remoteIp} ("));
        }

        /// <summary>Removes the block rules previously created for an
        /// application path (v2 + legacy naming plus exact
        /// ApplicationName). Returns the removal count.</summary>
        public Task<int> RemoveBlockRulesForAppAsync(string appPath)
        {
            return Task.Run(() =>
            {
                int removed = 0;
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    var names = new List<string>();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        try
                        {
                            string name = rule.Name ?? "";
                            string app = rule.ApplicationName ?? "";
                            if ((name.StartsWith("AutoCommand Process Block - ", StringComparison.OrdinalIgnoreCase) ||
                                 name.StartsWith(NewAppPrefix, StringComparison.OrdinalIgnoreCase)) &&
                                string.Equals(app, appPath, StringComparison.OrdinalIgnoreCase))
                            {
                                names.Add(name);
                            }
                        }
                        catch { }
                    }

                    foreach (string name in names)
                    {
                        try { fwPolicy.Rules.Remove(name); removed++; } catch { }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to remove firewall rules: {ex.Message}", ex);
                }
                return removed;
            });
        }

        private int RemoveRulesByNamePrefix(string namePrefix)
        {
            int removed = 0;
            try
            {
                dynamic fwPolicy = GetPolicy();
                // Collect matches first — removing while enumerating the COM collection is unreliable
                var names = new List<string>();
                foreach (dynamic rule in fwPolicy.Rules)
                {
                    try
                    {
                        string name = rule.Name ?? "";
                        if (name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase)) names.Add(name);
                    }
                    catch { }
                }

                foreach (string name in names)
                {
                    try { fwPolicy.Rules.Remove(name); removed++; } catch { }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to remove firewall rules: {ex.Message}", ex);
            }
            return removed;
        }

        // ── Live state (menu flip + ⛔ badges) ───────────────────────────

        public enum BlockState { None, Active, Paused }

        public class BlockSnapshot
        {
            public Dictionary<string, BlockState> Ips = new(StringComparer.OrdinalIgnoreCase);
            public Dictionary<string, BlockState> Apps = new(StringComparer.OrdinalIgnoreCase); // keyed on exe file name
            public DateTime TakenUtc;
        }

        private BlockSnapshot _snapshot = new() { TakenUtc = DateTime.MinValue };
        private readonly object _snapLock = new();

        /// <summary>Refreshes the live block-state cache from the firewall —
        /// one COM pass; states derive from rule presence + Enabled exactly
        /// like AutoCommand's Process Monitor (_activeIps / _pausedIps).</summary>
        public BlockSnapshot RefreshSnapshot()
        {
            var snap = new BlockSnapshot { TakenUtc = DateTime.UtcNow };
            try
            {
                dynamic fwPolicy = GetPolicy();
                foreach (dynamic rule in fwPolicy.Rules)
                {
                    if (!IsOurBlock(rule, out string name)) continue;
                    bool enabled;
                    try { enabled = (bool)rule.Enabled; } catch { enabled = true; }
                    string ip = ParseIpTargetIfIp(name);
                    if (ip != null)
                    {
                        snap.Ips[ip] = enabled ? BlockState.Active : BlockState.Paused;
                    }
                    else
                    {
                        string app = ParseAppTarget(name);
                        if (app.Length > 0)
                            snap.Apps[app] = enabled ? BlockState.Active : BlockState.Paused;
                    }
                }
            }
            catch { /* enumeration failed — keep prior snapshot */ }
            lock (_snapLock) _snapshot = snap;
            return snap;
        }

        public BlockSnapshot Snapshot()
        {
            lock (_snapLock) return _snapshot;
        }

        private static string ParseIpTargetIfIp(string name)
        {
            if (!(name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase) ||
                  name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase))) return null;
            string parsed = ParseIpTarget(name);
            return System.Net.IPAddress.TryParse(parsed, out _) ? parsed : null;
        }

        private static string ParseAppTarget(string name)
        {
            string prefix = name.StartsWith(NewAppPrefix, StringComparison.OrdinalIgnoreCase)
                ? NewAppPrefix : LegacyAppPrefix[0];
            string rest = name.Substring(prefix.Length).Trim();
            int cut = rest.IndexOf('(');
            return (cut > 0 ? rest[..cut] : rest).Trim();
        }

        public BlockState IpState(string ip)
        {
            var s = Snapshot();
            return s.Ips.TryGetValue(ip ?? "", out var st) ? st : BlockState.None;
        }

        /// <summary>App-block state for a full image path — matches on the
        /// exe file name, mirroring how v2 rules are named.</summary>
        public BlockState AppState(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return BlockState.None;
            var s = Snapshot();
            return s.Apps.TryGetValue(System.IO.Path.GetFileName(imagePath), out var st) ? st : BlockState.None;
        }

        // ── Emergency restore (the panic button) ─────────────────────────

        public class FleetToggleResult { public int Matched; public int Changed; public int SkippedRisky; public string FirstError; }

        /// <summary>A rule is "risky" when its target is Microsoft/CDN
        /// infrastructure or a Windows component — re-enabling those is what
        /// re-breaks internet, updates or notifications after a panic restore.</summary>
        private static bool IsRiskyRule(string name, dynamic rule)
        {
            try
            {
                if (name.StartsWith(NewIpPrefix, StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith(LegacyIpPrefix[0], StringComparison.OrdinalIgnoreCase))
                    return IpClassifier.IsMicrosoftInfra(ParseIpTarget(name));
                string app = rule.ApplicationName ?? "";
                return app.Length > 0 && app.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>
        /// Emergency internet restore / re-enable — the exact AutoCommand
        /// semantics. With skipRisky=true, rules targeting Microsoft/CDN
        /// infrastructure or Windows components are left in their current
        /// state — the "restore everything except the problematic ones"
        /// path after a panic disable.
        /// </summary>
        public Task<FleetToggleResult> SetAllBlocksEnabledAsync(bool enabled, bool skipRisky = false)
        {
            return Task.Run(() =>
            {
                var result = new FleetToggleResult();
                try
                {
                    dynamic fwPolicy = GetPolicy();
                    foreach (dynamic rule in fwPolicy.Rules)
                    {
                        if (!IsOurBlock(rule, out string name)) continue;
                        if (skipRisky && enabled && IsRiskyRule(name, rule))
                        {
                            result.SkippedRisky++;
                            continue;
                        }
                        result.Matched++;
                        try
                        {
                            bool was = (bool)rule.Enabled;
                            rule.Enabled = enabled;
                            if (was != enabled) result.Changed++;
                        }
                        catch (Exception ex) { if (result.FirstError == null) result.FirstError = ex.Message; }
                    }
                }
                catch (Exception ex) { result.FirstError = ex.Message; }
                return result;
            });
        }
    }
}
