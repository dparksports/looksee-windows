using System;
using System.IO;
using System.Text;
using System.Windows;
using LookSee.Models;

namespace LookSee.Views
{
    /// <summary>
    /// Read-only preview of one delivered BITS file — the explicit opt-in
    /// action per the app's observational-default rule. Text-like files
    /// show their first 64 KB as UTF-8; binaries show a hex dump of the
    /// first 4 KB with a "hash only" notice. Nothing is persisted or
    /// exported; the file is opened with read-only, share-all access.
    /// </summary>
    public partial class BitsContentPreviewWindow : Window
    {
        private const int TextLimitBytes = 64 * 1024;
        private const int HexLimitBytes = 4 * 1024;

        public BitsContentPreviewWindow(BitsFileRef file, string jobName)
        {
            InitializeComponent();
            HeaderText.Text = $"Job \"{jobName ?? "?"}\" — delivered file preview";
            Load(file);
        }

        private void Load(BitsFileRef file)
        {
            if (file == null || string.IsNullOrEmpty(file.LocalName))
            {
                ContentText.Text = "No local path known for this file (job predates live tracing).";
                return;
            }
            if (!File.Exists(file.LocalName))
            {
                ContentText.Text = $"File no longer exists at:\n{file.LocalName}\n\nBITS removes/moves temp files after the job completes; the SHA-256 below was captured at completion time.";
                FileMetaText.Text = MetaLine(file);
                return;
            }

            try
            {
                FileMetaText.Text = MetaLine(file);
                using var stream = new FileStream(file.LocalName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                int toRead = (int)Math.Min(stream.Length, TextLimitBytes);
                byte[] buffer = new byte[toRead];
                int read = 0;
                while (read < toRead)
                {
                    int n = stream.Read(buffer, read, toRead - read);
                    if (n <= 0) break;
                    read += n;
                }

                bool looksBinary = LooksBinary(buffer, Math.Min(read, 4096));
                if (looksBinary)
                {
                    int hexLen = Math.Min(read, HexLimitBytes);
                    ContentText.Text = "(binary file — showing a hex dump of the first 4 KB only; use the SHA-256 to identify it)\n\n" + HexDump(buffer, hexLen);
                }
                else
                {
                    // Strict UTF-8 decode; fall back to hex if the tail is invalid
                    try
                    {
                        string text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(buffer, 0, read);
                        ContentText.Text = read < stream.Length
                            ? text + $"\n\n… (first {TextLimitBytes / 1024} KB of {stream.Length:N0} bytes)"
                            : text;
                    }
                    catch (DecoderFallbackException)
                    {
                        ContentText.Text = "(not valid UTF-8 — hex dump of the first 4 KB)\n\n" + HexDump(buffer, Math.Min(read, HexLimitBytes));
                    }
                }
            }
            catch (Exception ex)
            {
                ContentText.Text = $"Could not read the file: {ex.Message}";
            }
        }

        private static string MetaLine(BitsFileRef file)
        {
            string size = file.LocalSize is long n ? $"{n:N0} bytes" : "size unknown";
            string hash = string.IsNullOrEmpty(file.Sha256) ? "hash pending" : file.Sha256;
            return $"{file.LocalName}\n{size} · SHA-256 {hash}";
        }

        private static bool LooksBinary(byte[] buffer, int length)
        {
            // A NUL byte in the leading window is the classic text/binary discriminator.
            for (int i = 0; i < length; i++)
                if (buffer[i] == 0) return true;
            return false;
        }

        private static string HexDump(byte[] buffer, int length)
        {
            var sb = new StringBuilder();
            for (int offset = 0; offset < length; offset += 16)
            {
                int lineLen = Math.Min(16, length - offset);
                sb.Append(offset.ToString("X8")).Append("  ");
                for (int i = 0; i < 16; i++)
                {
                    if (i < lineLen) sb.Append(buffer[offset + i].ToString("X2")).Append(' ');
                    else sb.Append("   ");
                    if (i == 7) sb.Append(' ');
                }
                sb.Append(' ');
                for (int i = 0; i < lineLen; i++)
                {
                    byte b = buffer[offset + i];
                    sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }
    }
}
