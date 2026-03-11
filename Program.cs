using Spectre.Console;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;

// ── Encoding ──────────────────────────────────────────────────────────────────
Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding  = Encoding.UTF8;

// ── Globals ───────────────────────────────────────────────────────────────────
var tempPath = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar).ToLower();

var dangerousExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".bat", ".vbs", ".ps1", ".cmd", ".scr", ".pif", ".com", ".hta", ".jar" };

var documentExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".mp4", ".mp3", ".zip" };

var knownMalware = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    // RATs
    "darkcomet","njrat","nanocore","asyncrat","remcos","quasar","xworm","dcrat",
    "netbus","subseven","bifrost","blackshades","cybergate","xtremerat",
    "adwind","poisonivy","darktrack","imminent","pandora","warzone",
    // Stealers
    "redline","vidar","raccoon","azorult","arkei","predator","titan","loki",
    "pony","hawkeye","formbook","agenttesla","masslogger","snakekeylogger","rhadamanthys",
    // Trojans / Loaders
    "emotet","trickbot","qakbot","dridex","ursnif","zloader","smokeloader",
    "bumblebee","icedid","gozi","amadey","tofsee",
    // Ransomware
    "ryuk","conti","lockbit","revil","sodinokibi","dharma","wannacry","notpetya","djvu",
    // Miners
    "xmrig","minerd","cpuminer",
    // C2 frameworks
    "meterpreter","cobaltstrike","cobaltstr","sliver","havoc","brute-ratel","bruteratel",
};

// Known-good app paths inside AppData — prevents false positives on legitimate software
var legitAppDataPaths = new string[]
{
    @"\microsoft\", @"\google\chrome\", @"\discord\", @"\slack\", @"\spotify\",
    @"\zoom\", @"\teams\", @"\steam\", @"\obs studio\", @"\signal\",
    @"\1password\", @"\nordvpn\", @"\vlc\", @"\notepad++\", @"\jetbrains\",
    @"\code\", @"\visual studio\", @"\mozilla\", @"\onedrive\", @"\dropbox\",
    @"\whatsapp\", @"\telegram\", @"\opera\", @"\brave\", @"\vivaldi\",
    @"\malwarebytes\", @"\windows defender\",
    @"\anthropic\", @"\claude\", @"\anthropicclaude\",
    @"\riot games\", @"\riotgames\", @"\epicgames\", @"\epic games\",
    // Standard user-install location (VS Code, Python, Node, Electron apps)
    @"\appdata\local\programs\",
    // Common legitimate apps
    @"\cursor\", @"\windsurf\", @"\warp\",
    @"\python\", @"\node\", @"\nodejs\",
    @"\logitech\", @"\razer\", @"\steelseries\", @"\corsair\", @"\asus\",
    @"\nordvpn\", @"\expressvpn\", @"\protonvpn\", @"\mullvad\",
    @"\easyantiacheat\", @"\battleye\", @"\vanguard\",
    @"\adobe\", @"\autodesk\",
    @"\nvidia\", @"\amd\", @"\intel\",
    @"\git\", @"\github desktop\", @"\gitkraken\",
    @"\figma\", @"\notion\", @"\obsidian\",
};

// Legitimate temp subfolders — Visual Studio, .NET, ASP.NET, installers put real files here
var legitTempPaths = new string[]
{
    @"\roslyn\", @"\temporary asp.net", @"\vbcscompiler\", @"\nuget\",
    @"\dotnet\", @"\vs-", @"\visualstudio\", @"\microsoft.net\",
    @"\jetbrains\", @"\rider\", @"\clion\",
    @"\nvidia\", @"\amd\", @"\intel\",
    @"\winget\", @"\chocolatey\", @"\scoop\",
    @"\7z", @"\mozilla\", @"\firefox\", @"\chrome\",
    @"\windowsapps\", @"\winapps\",
};

// Trusted Authenticode signers — signed by these = skip
var trustedPublishers = new string[]
{
    "Microsoft Corporation","Microsoft Windows","Google LLC","Discord Inc.",
    "Spotify AB","Slack Technologies","Valve Corporation","Zoom Video",
    "Apple Inc.","Adobe Inc.","Oracle America","Mozilla Corporation",
    "Dropbox","Telegram","NVIDIA","Intel","AMD","Logitech","Razer",
};

// Suspicious ports used by RATs and C2 frameworks
var suspiciousPorts = new HashSet<int> { 1177,1604,4444,5554,5555,6666,6667,6668,7777,8888,9999,31337,12345,54321,1337,65000 };

// Suspicious PowerShell command patterns
var suspiciousCmdPatterns = new string[]
{
    "-encodedcommand","-enc ","-e ","iex(","invoke-expression","invoke-webrequest",
    "downloadstring","downloadfile","webclient","hidden","bypass",
    "certutil -decode","certutil -urlcache","bitsadmin /transfer",
    "mshta javascript:","regsvr32 /s /n","-noninteractive","frombase64",
    "system.reflection","[convert]::","net user /add","net localgroup administrators",
};

var lastFindings = new List<Finding>();
CancellationTokenSource? proxyTokenSource = null;

// ── Helpers ───────────────────────────────────────────────────────────────────
string ResolvePath(string input)
{
    var parts = input.Trim().Replace('/', '\\').Split('\\', 2);
    var base_ = parts[0].ToLower() switch
    {
        "desktop"      => Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        "downloads"    => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        "documents"    => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        "temp"         => Path.GetTempPath(),
        "appdata"      => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "localappdata" => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "system"       => Environment.GetFolderPath(Environment.SpecialFolder.System),
        _              => parts[0]
    };
    return parts.Length == 2 ? Path.Combine(base_, parts[1]) : base_;
}

string? GetAuthenticodeSigner(string path)
{
    try
    {
        var cert = X509Certificate.CreateFromSignedFile(path);
        return cert.Subject.Split(',')
            .FirstOrDefault(p => p.Trim().StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            ?.Substring(3).Trim() ?? cert.Subject;
    }
    catch { return null; }
}

bool IsTrustedSigner(string path)
{
    var signer = GetAuthenticodeSigner(path);
    if (signer == null) return false;
    return trustedPublishers.Any(t => signer.Contains(t, StringComparison.OrdinalIgnoreCase));
}

bool HasPeHeader(string path)
{
    try
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buf = new byte[2];
        return fs.Read(buf, 0, 2) == 2 && buf[0] == 0x4D && buf[1] == 0x5A;
    }
    catch { return false; }
}

double ComputeEntropy(string path)
{
    try
    {
        const int maxBytes = 65536;
        using var fs = File.OpenRead(path);
        var buffer = new byte[Math.Min(maxBytes, (int)Math.Min(fs.Length, maxBytes))];
        int read = fs.Read(buffer, 0, buffer.Length);
        if (read < 256) return 0;
        var freq = new int[256];
        for (int i = 0; i < read; i++) freq[buffer[i]]++;
        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / read;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
    catch { return 0; }
}

string RunCommand(string cmd, string args, int timeoutMs = 10000)
{
    try
    {
        var psi = new ProcessStartInfo(cmd, args)
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(timeoutMs);
        return output;
    }
    catch { return ""; }
}

bool IsInLegitPath(string path) =>
    legitAppDataPaths.Any(p => path.ToLower().Contains(p));

bool IsLegitTempPath(string path) =>
    legitTempPaths.Any(p => path.ToLower().Contains(p));

// Word-boundary malware name match — prevents "conti" matching "Continue", "emotet" matching "Remote"
bool MatchesMalware(string text, string malware)
{
    int idx = text.IndexOf(malware, StringComparison.OrdinalIgnoreCase);
    if (idx < 0) return false;
    bool startOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
    bool endOk   = idx + malware.Length >= text.Length || !char.IsLetterOrDigit(text[idx + malware.Length]);
    return startOk && endOk;
}

// ── Welcome ───────────────────────────────────────────────────────────────────
ShowWelcome();

bool isAdmin = new System.Security.Principal.WindowsPrincipal(
    System.Security.Principal.WindowsIdentity.GetCurrent())
    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
if (!isAdmin)
    AnsiConsole.MarkupLine("[yellow]  Tip: Run as Administrator for a more complete scan (some areas are locked without it).[/]\n");

// ── Main Loop ─────────────────────────────────────────────────────────────────
while (true)
{
    AnsiConsole.WriteLine();
    var choice = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[bold mediumpurple1]Select an option:[/]")
            .HighlightStyle(Style.Parse("bold mediumpurple1"))
            .AddChoiceGroup("Scan", "Full System Scan", "Scan Directory", "Scan Running Processes",
                "Scan Startup & Persistence", "Scan Scheduled Tasks", "Check Hosts File",
                "Check WMI Persistence", "Show Network Connections", "Hash a File",
                "Deep File Scan")
            .AddChoiceGroup("Network", "Block a Connection", "Manage Blocked IPs", "Live Traffic Monitor", "DPI Bypass")
            .AddChoiceGroup("", "Exit")
    );
    AnsiConsole.WriteLine();

    try
    {
        switch (choice)
        {
            case "Full System Scan":          RunFullScan();             break;
            case "Scan Directory":            ScanDirectory();           break;
            case "Scan Running Processes":    ScanProcesses();           break;
            case "Scan Startup & Persistence":ScanStartup();             break;
            case "Scan Scheduled Tasks":      ScanScheduledTasks();      break;
            case "Check Hosts File":          ScanHostsFile();           break;
            case "Check WMI Persistence":     ScanWmiPersistence();      break;
            case "Show Network Connections":  ShowNetworkConnections();  break;
            case "Hash a File":               HashFile();                break;
            case "Deep File Scan":           DeepFileScan();            break;
            case "Block a Connection":        BlockConnection();         break;
            case "Manage Blocked IPs":        ManageBlockedIPs();        break;
            case "Live Traffic Monitor":      LiveTrafficMonitor();      break;
            case "DPI Bypass":               DpiBypass();               break;
            case "Exit":
                if (proxyTokenSource != null)
                {
                    proxyTokenSource.Cancel();
                    RunCommand("powershell", "-NoProfile -NonInteractive -Command \"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0 -Type DWord\"", 5000);
                }
                return;
        }
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[red]Something went wrong: {Markup.Escape(ex.Message)}[/]");
    }

    if (lastFindings.Any(f => f.Risk is "HIGH" or "MEDIUM"))
        if (AnsiConsole.Confirm("\n[mediumpurple1]Save a report to your Desktop?[/]"))
            ExportReport();

    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[grey]Press any key to go back to the menu...[/]");
    Console.ReadKey(true);
}

// ─────────────────────────────────────────────────────────────────────────────
void ShowWelcome()
{
    var layout = new Table().NoBorder().HideHeaders()
        .AddColumn(new TableColumn("l").Width(32).PadRight(2))
        .AddColumn(new TableColumn("r"));

    var art =
        "⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠀⠖⠉⠉⠉⠁⢈⣽⣟⠲⣄⠀⠀⠀⠀⣠⠤⣄⣀⣀⡀⠀⠀⠀⠀\n" +
        "⢰⠀⠀⠀⠀⠀⣾⢿⣿⠀⣇⠀⠀⠀⢰⠃⣰⣶⣦⠀⠉⠓⠤⣀⠀\n" +
        "⠈⡄⠀⠀⠀⣴⠟⣟⡇⠀⡟⠀⠀⢠⡏⠀⣿⣿⡿⠀⠀⠀⠀⠈⠇\n" +
        "⠀⢱⠀⣀⡼⠹⡀⡼⠀⠰⡇⠀⠀⣸⠇⠀⡗⠋⣧⠀⠀⠀⠀⡸⠀\n" +
        "⠀⠘⠈⠸⡇⠀⠘⢥⠀⠀⢻⣀⡼⠁⠀⠠⡃⠔⠹⡄⠀⢀⡜⠁⠀\n" +
        "⠀⠀⠀⠀⠹⡀⠀⣀⣤⠤⣬⠥⢄⠀⠐⠋⠀⠀⡴⠍⠣⡘⠀⠀⠀\n" +
        "⠀⠀⠀⢀⣼⠚⠉⡁⠀⠀⠙⠒⢄⡈⠠⡈⠢⡊⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠀⠀⢠⡟⠁⠀⢰⠁⠀⠀⠀⠀⠀⠀⠀⠈⢢⣇⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠀⣀⣿⡔⢀⣀⣾⡀⠀⠀⢀⠄⠀⠀⢠⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠀⢼⢹⢳⣿⣿⣿⣿⡆⢀⠆⣠⣴⣦⣾⡀⢣⠸⠀⠀⠀⠀⠀⠀⠀\n" +
        "⢀⣰⠎⢸⣿⣿⣿⡿⠁⡆⡆⣿⣿⣿⣿⣷⣠⡀⠀⠀⠀⠀⠀⠀⠀\n" +
        "⢎⡁⠀⠀⠀⠏⠁⢠⡾⢷⡇⠈⢿⢿⣿⣿⢸⡏⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠈⢷⣤⣤⣤⡀⠄⠀⠁⠈⠛⠀⠀⠸⠁⠉⠀⠳⡄⠀⠀⠀⠀⠀⠀\n" +
        "⠀⠀⠀⢈⡷⢧⣀⡀⡄⢀⠀⠋⣽⡷⠦⣤⡴⠞⠁⠀⠀⠀⠀⠀⠀\n" +
        "⠀⠀⠀⠘⠷⢦⢧⣥⣏⣹⣱⣾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";

    layout.AddRow(
        new Rows(
            new Text(art, new Style(Color.MediumPurple1)),
            new Markup("[pink1]₍ᐢ. .ᐢ₎[/]  [bold white]Robb-IT Security[/]"),
            new Markup("[grey]         v2.0 · Defense Tool[/]")
        ),
        new Markup(
            "[bold mediumpurple1]What can I do?[/]\n[grey]──────────────────────────────────[/]\n" +
            "[pink1]>[/] [white]Full System Scan[/]       [grey]check everything at once[/]\n" +
            "[grey]>[/] [white]Scan Directory[/]         [grey]check a folder for threats[/]\n" +
            "[grey]>[/] [white]Scan Processes[/]         [grey]check running programs[/]\n" +
            "[grey]>[/] [white]Startup & Persistence[/]  [grey]what launches on boot[/]\n" +
            "[grey]>[/] [white]Scheduled Tasks[/]        [grey]hidden auto-running tasks[/]\n" +
            "[grey]>[/] [white]Hosts File[/]             [grey]detect phishing redirects[/]\n" +
            "[grey]>[/] [white]WMI Persistence[/]        [grey]advanced malware hiding spot[/]\n" +
            "[grey]>[/] [white]Network Connections[/]    [grey]what's connecting to internet[/]\n" +
            "[grey]>[/] [white]Hash a File[/]            [grey]get file fingerprint[/]"
        )
    );

    AnsiConsole.Write(new Panel(layout)
        .Header("[bold mediumpurple1] Robb-IT Security v2.0 [/]")
        .BorderColor(Color.MediumPurple1).Padding(1, 0));
}

// ─────────────────────────────────────────────────────────────────────────────
void RunFullScan()
{
    var all = new List<Finding>();
    AnsiConsole.MarkupLine("[bold mediumpurple1]Running full system scan...[/]\n");

    AnsiConsole.Progress()
        .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new SpinnerColumn())
        .Start(ctx =>
        {
            var t1 = ctx.AddTask("[white]Startup & Persistence[/]", maxValue: 1);
            var t2 = ctx.AddTask("[white]Running Processes[/]", maxValue: 1);
            var t3 = ctx.AddTask("[white]Scheduled Tasks[/]", maxValue: 1);
            var t4 = ctx.AddTask("[white]WMI Persistence[/]", maxValue: 1);
            var t5 = ctx.AddTask("[white]Hosts File[/]", maxValue: 1);
            var t6 = ctx.AddTask("[white]Common Malware Paths[/]", maxValue: 1);

            CollectStartup(all);   t1.Increment(1);
            CollectProcesses(all); t2.Increment(1);
            CollectScheduledTasks(all); t3.Increment(1);
            CollectWmi(all);       t4.Increment(1);
            CollectHostsFile(all); t5.Increment(1);

            // Scan temp + downloads for common paths
            foreach (var scanPath in new[] { Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads") })
                if (Directory.Exists(scanPath)) CollectDirectory(scanPath, all);
            t6.Increment(1);
        });

    lastFindings = all;
    PrintFindings(all, "Full System Scan");
}

// ─────────────────────────────────────────────────────────────────────────────
void ScanDirectory()
{
    var path = PickFolder();
    if (path == null) return;
    if (!Directory.Exists(path)) { AnsiConsole.MarkupLine($"[red]Folder not found: {Markup.Escape(path)}[/]"); return; }
    AnsiConsole.MarkupLine($"[grey]Scanning: {Markup.Escape(path)}[/]\n");

    var findings = new List<Finding>();
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Scanning files...[/]", _ => CollectDirectory(path, findings));

    lastFindings = findings;
    PrintFindings(findings, "Folder Scan");
}

void CollectDirectory(string path, List<Finding> findings)
{
    IEnumerable<string> files;
    try   { files = Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories); }
    catch { files = Directory.EnumerateFiles(path, "*", SearchOption.TopDirectoryOnly); }

    int scanned = 0;
    const int maxFiles = 10_000;

    foreach (var file in files)
    {
        if (++scanned > maxFiles) break;
        try
        {
            var name = Path.GetFileName(file);
            var ext  = Path.GetExtension(file);
            var dir  = (Path.GetDirectoryName(file) ?? "").ToLower();

            // 1. File disguised as document but has PE header (MZ magic bytes)
            if (IsLegitTempPath(file)) continue;

            if (documentExts.Contains(ext) && HasPeHeader(file))
            {
                findings.Add(new Finding(file,
                    $"This file claims to be a {ext.ToUpper()} but is actually an executable program — classic malware disguise",
                    "Do NOT open it. Delete it immediately.",
                    "HIGH", "File"));
                continue;
            }

            // 2. Double extension (e.g. invoice.pdf.exe)
            var parts = name.Split('.');
            if (parts.Length >= 3 && dangerousExts.Contains("." + parts[^1]) && documentExts.Contains("." + parts[^2]))
            {
                findings.Add(new Finding(file,
                    $"File has a fake extension — it looks like a {parts[^2].ToUpper()} but runs as a program",
                    "Do NOT open it. Delete immediately.",
                    "HIGH", "File")); continue;
            }

            // 3. Executable in suspicious location
            if (dangerousExts.Contains(ext))
            {
                // Skip trusted signers
                if (IsTrustedSigner(file)) continue;

                string dirLow = dir;
                if (dirLow.StartsWith(tempPath) || dirLow.Contains("\\temp\\"))
                {
                    findings.Add(new Finding(file,
                        "Executable program found in a temporary folder — legitimate software never lives here",
                        "Investigate and delete if you don't recognise it.",
                        "HIGH", "File")); continue;
                }

                if (dirLow.Contains("\\appdata\\") && !IsInLegitPath(dirLow))
                {
                    // Check entropy — high entropy = packed/encrypted
                    double entropy = ComputeEntropy(file);
                    string risk = entropy > 7.2 ? "HIGH" : "MEDIUM";
                    string entropyNote = entropy > 7.2 ? $" (high entropy: {entropy:F1}/8.0 — likely packed or encrypted)" : "";
                    findings.Add(new Finding(file,
                        $"Unknown program in a hidden folder{entropyNote}",
                        "Check if you recognise it. Delete if unknown.",
                        risk, "File")); continue;
                }

                // High entropy executable — skip for installers and Downloads (packed installers are normal)
                bool isInstaller = name.Contains("install", StringComparison.OrdinalIgnoreCase)
                                || name.Contains("setup", StringComparison.OrdinalIgnoreCase)
                                || name.Contains("update", StringComparison.OrdinalIgnoreCase)
                                || name.Contains("uninstall", StringComparison.OrdinalIgnoreCase);
                bool isDownloads = dir.Contains("\\downloads\\")
                                || dir.Contains("\\appdata\\local\\programs\\");
                if (!isInstaller && !isDownloads)
                {
                    double ent = ComputeEntropy(file);
                    if (ent > 7.4)
                    {
                        findings.Add(new Finding(file,
                            $"Program file has very high entropy ({ent:F1}/8.0) — may be packed or encrypted",
                            "Scan with antivirus. High entropy executables are often packed malware.",
                            "MEDIUM", "File")); continue;
                    }
                }
            }

            // 4. Known malware name
            foreach (var m in knownMalware)
                if (MatchesMalware(name, m))
                {
                    findings.Add(new Finding(file,
                        $"File name matches known malware: \"{m}\"",
                        "Delete immediately and run a full antivirus scan.",
                        "HIGH", "File")); break;
                }

            // 5. Hidden executable
            var attr = File.GetAttributes(file);
            if (attr.HasFlag(FileAttributes.Hidden) && dangerousExts.Contains(ext) && !IsTrustedSigner(file))
                findings.Add(new Finding(file,
                    "This program file is intentionally hidden from view",
                    "Highly suspicious. Investigate and remove if unknown.",
                    "HIGH", "File"));
        }
        catch { }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void ScanProcesses()
{
    var findings = new List<Finding>();
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Checking running programs...[/]", _ => CollectProcesses(findings));
    lastFindings = findings;
    PrintFindings(findings, "Running Programs Scan");
}

void CollectProcesses(List<Finding> findings)
{
    // Get command lines via PowerShell (wmic is deprecated/removed on Windows 11)
    var cmdLines = new Dictionary<int, string>();
    var psOutput = RunCommand("powershell",
        "-NoProfile -NonInteractive -Command \"Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId.ToString() + '|' + $_.CommandLine }\"",
        12000);
    foreach (var line in psOutput.Split('\n'))
    {
        var sep = line.IndexOf('|');
        if (sep < 1) continue;
        if (int.TryParse(line[..sep].Trim(), out int psPid))
            cmdLines[psPid] = line[(sep + 1)..].Trim().ToLower();
    }

    foreach (var proc in Process.GetProcesses())
    {
        try
        {
            string location = "";
            try { location = proc.MainModule?.FileName ?? ""; } catch { continue; }
            if (string.IsNullOrEmpty(location)) continue;

            var loc = location.ToLower();

            // Skip trusted signers — major false positive reducer
            if (IsTrustedSigner(location)) continue;
            if (IsInLegitPath(loc)) continue;

            string reason = "", action = "", risk = "";

            // Location checks
            if (loc.StartsWith(tempPath) || loc.Contains("\\temp\\"))
            {
                reason = "This program is running from a temporary folder — legitimate apps never do this";
                action = "End this process immediately. Right-click in Task Manager and choose End Task.";
                risk = "HIGH";
            }
            else if (loc.Contains("\\appdata\\local\\temp"))
            {
                reason = "Running from a hidden temp folder";
                action = "End this process and investigate the file.";
                risk = "HIGH";
            }
            else if (loc.Contains("\\appdata\\roaming\\") || loc.Contains("\\appdata\\local\\"))
            {
                reason = "Running from a hidden AppData folder (not a known legitimate app)";
                action = "Check if you recognise it. End the process and delete the file if unknown.";
                risk = "MEDIUM";
            }

            // Known malware name
            foreach (var m in knownMalware)
                if (MatchesMalware(proc.ProcessName, m))
                {
                    reason = $"Process name matches known malware: \"{m}\"";
                    action = "End this process immediately and run a full antivirus scan.";
                    risk = "HIGH"; break;
                }

            // Command line suspicious patterns
            if (cmdLines.TryGetValue(proc.Id, out var cmdLine))
            {
                foreach (var pattern in suspiciousCmdPatterns)
                {
                    if (cmdLine.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        if (string.IsNullOrEmpty(risk)) risk = "HIGH";
                        reason = $"Suspicious command-line argument detected: \"{pattern}\"";
                        action = "This is a common malware or hacker technique. Investigate immediately.";
                        break;
                    }
                }
            }

            if (!string.IsNullOrEmpty(risk))
                findings.Add(new Finding($"{proc.ProcessName}  (PID: {proc.Id})", reason, action, risk, "Process"));
        }
        catch { }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void ScanStartup()
{
    var findings = new List<Finding>();
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Checking startup & persistence...[/]", _ => CollectStartup(findings));
    lastFindings = findings;
    PrintFindings(findings, "Startup & Persistence Scan", showInfo: true);
}

void CollectStartup(List<Finding> findings)
{
    var entries = new[]
    {
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     Registry.CurrentUser,  "Run (Your account)"),
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     Registry.LocalMachine, "Run (All users)"),
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser,  "RunOnce (Your account)"),
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine, "RunOnce (All users)"),
    };

    // AppInit_DLLs — check only this specific value (anything non-empty here is suspicious)
    try
    {
        using var winKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
        var appInit = winKey?.GetValue("AppInit_DLLs")?.ToString() ?? "";
        if (!string.IsNullOrWhiteSpace(appInit))
            findings.Add(new Finding($"AppInit_DLLs: {appInit}",
                $"A DLL is set to load into every Windows process: {appInit}",
                "This is very unusual. Remove it unless you explicitly set it.",
                "HIGH", "Startup"));
    }
    catch { }

    // Winlogon — only check Shell and Userinit for tampering
    try
    {
        using var wlKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        var shell = wlKey?.GetValue("Shell")?.ToString() ?? "";
        var userinit = wlKey?.GetValue("Userinit")?.ToString() ?? "";
        if (!string.IsNullOrEmpty(shell) && !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            findings.Add(new Finding($"Winlogon Shell: {shell}",
                "The Windows shell has been replaced — malware uses this to run on login",
                "This should be 'explorer.exe'. Restore it immediately if you didn't change it.",
                "HIGH", "Startup"));
        if (!string.IsNullOrEmpty(userinit) && !userinit.ToLower().Contains("userinit.exe"))
            findings.Add(new Finding($"Winlogon Userinit: {userinit}",
                "The Windows login process has been modified",
                "This should contain 'userinit.exe'. Restore it if you didn't change it.",
                "HIGH", "Startup"));
    }
    catch { }

    foreach (var (keyPath, hive, label) in entries)
    {
        try
        {
            using var key = hive.OpenSubKey(keyPath);
            if (key == null) continue;

            foreach (var valueName in key.GetValueNames())
            {
                var value  = key.GetValue(valueName)?.ToString() ?? "";
                var valLow = value.ToLower();
                string reason = "", action = "", risk = "INFO";

                if (valLow.Contains("\\temp\\") || valLow.StartsWith(tempPath))
                {
                    reason = "Auto-starts from a temporary folder on every boot";
                    action = "Remove immediately. Open Task Manager → Startup tab to disable.";
                    risk = "HIGH";
                }
                else if (valLow.Contains("\\appdata\\") && !IsInLegitPath(valLow))
                {
                    reason = "Auto-starts from a hidden folder on every boot";
                    action = "Check if you recognise this. Remove from startup if unknown.";
                    risk = "MEDIUM";
                }

                foreach (var m in knownMalware)
                    if (MatchesMalware(valueName, m) || MatchesMalware(value, m))
                    {
                        reason = $"Name matches known malware: \"{m}\"";
                        action = "Remove from startup and delete the file. Run antivirus scan.";
                        risk = "HIGH"; break;
                    }

                if (string.IsNullOrEmpty(reason))
                {
                    string display = value.Length > 55 ? value[..55] + "..." : value;
                    reason = $"Starts automatically — {display}";
                    action = "Normal if you recognise it. Remove if you don't.";
                }

                findings.Add(new Finding($"{valueName}  [{label}]", reason, action, risk, "Startup"));
            }
        }
        catch { }
    }

    // Startup folder
    foreach (var file in Directory.EnumerateFiles(Environment.GetFolderPath(Environment.SpecialFolder.Startup)))
    {
        var ext = Path.GetExtension(file);
        string risk = dangerousExts.Contains(ext) ? "MEDIUM" : "INFO";
        findings.Add(new Finding(Path.GetFileName(file),
            "This file runs automatically when Windows starts",
            risk == "MEDIUM" ? "Verify you recognise this program." : "Normal if you recognise it.",
            risk, "Startup"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void ScanScheduledTasks()
{
    var findings = new List<Finding>();
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Scanning scheduled tasks...[/]", _ => CollectScheduledTasks(findings));
    lastFindings = findings;
    PrintFindings(findings, "Scheduled Tasks Scan");
}

void CollectScheduledTasks(List<Finding> findings)
{
    var output = RunCommand("schtasks", "/query /fo CSV /v", 15000);
    var lines = output.Split('\n');
    string? header = lines.FirstOrDefault(l => l.Contains("TaskName"));
    if (header == null) return;

    // Detect column positions from actual header instead of hardcoding
    var headerCols = ParseCsv(header);
    int taskNameIdx = -1, taskActionIdx = -1;
    for (int i = 0; i < headerCols.Length; i++)
    {
        var h = headerCols[i].Trim('"', ' ');
        if (h == "TaskName")    taskNameIdx   = i;
        if (h == "Task To Run") taskActionIdx = i;
    }
    if (taskNameIdx < 0 || taskActionIdx < 0) return;

    foreach (var line in lines.Skip(1))
    {
        if (string.IsNullOrWhiteSpace(line)) continue;
        var cols = ParseCsv(line);
        if (cols.Length <= taskActionIdx) continue;

        string taskName   = cols[taskNameIdx].Trim('"', ' ');
        string taskAction = cols[taskActionIdx].Trim('"', ' ');
        if (string.IsNullOrEmpty(taskName) || taskName == "TaskName") continue;

        string reason = "", action = "", risk = "";
        var actionLow = taskAction.ToLower();

        if (actionLow.Contains("\\temp\\") || actionLow.StartsWith(tempPath))
        {
            reason = "Scheduled task runs a program from a temporary folder — very suspicious";
            action = "Open Task Scheduler and delete this task immediately.";
            risk = "HIGH";
        }
        else if (actionLow.Contains("\\appdata\\") && !IsInLegitPath(actionLow))
        {
            reason = "Scheduled task runs a program from a hidden folder";
            action = "Verify in Task Scheduler. Delete if you don't recognise it.";
            risk = "MEDIUM";
        }
        else
        {
            foreach (var m in knownMalware)
                if (MatchesMalware(taskName, m) || MatchesMalware(taskAction, m))
                {
                    reason = $"Task name/action matches known malware: \"{m}\"";
                    action = "Delete this task immediately from Task Scheduler.";
                    risk = "HIGH"; break;
                }
        }

        if (!string.IsNullOrEmpty(risk))
        {
            string display = taskAction.Length > 55 ? taskAction[..55] + "..." : taskAction;
            findings.Add(new Finding(taskName, reason, action, risk, "Task"));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void ScanHostsFile()
{
    var findings = new List<Finding>();
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Checking hosts file...[/]", _ => CollectHostsFile(findings));
    lastFindings = findings;
    if (findings.Count == 0)
        AnsiConsole.MarkupLine("[green]✓ Hosts file looks clean — no suspicious redirects found.[/]");
    else
        PrintFindings(findings, "Hosts File Check");
}

void CollectHostsFile(List<Finding> findings)
{
    var hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
    if (!File.Exists(hostsPath)) return;

    var importantDomains = new[] {
        "microsoft.com","windowsupdate.com","google.com","gmail.com","youtube.com",
        "facebook.com","amazon.com","apple.com","avast.com","kaspersky.com",
        "malwarebytes.com","norton.com","mcafee.com","bitdefender.com","eset.com",
    };

    foreach (var line in File.ReadAllLines(hostsPath))
    {
        var trimmed = line.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#')) continue;
        var parts = trimmed.Split(new[] {' ', '\t'}, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) continue;

        string ip = parts[0], domain = parts[1];
        bool isLoopback = ip is "127.0.0.1" or "::1" or "0.0.0.0";

        if (!isLoopback)
        {
            bool isKnown = importantDomains.Any(d => domain.EndsWith(d, StringComparison.OrdinalIgnoreCase));
            string risk = isKnown ? "HIGH" : "MEDIUM";
            string reason = isKnown
                ? $"'{domain}' is redirected to '{ip}' — this could hijack your connection to a fake site"
                : $"Custom redirect: '{domain}' → '{ip}'";
            string act = isKnown
                ? "Remove this line from the hosts file immediately. This could be a phishing attack."
                : "Verify if you added this. Remove if you didn't.";
            findings.Add(new Finding($"{domain} → {ip}", reason, act, risk, "Hosts"));
        }
        else if (importantDomains.Any(d => domain.EndsWith(d, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding($"{domain} → blocked",
                $"'{domain}' is blocked — this may prevent antivirus updates or Windows updates",
                "Remove this line unless you specifically blocked this domain on purpose.",
                "MEDIUM", "Hosts"));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void ScanWmiPersistence()
{
    var findings = new List<Finding>();
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Checking WMI persistence...[/]", _ => CollectWmi(findings));
    lastFindings = findings;
    if (findings.Count == 0)
        AnsiConsole.MarkupLine("[green]✓ No WMI persistence found — this is the expected result on a clean PC.[/]");
    else
        PrintFindings(findings, "WMI Persistence Check");
}

void CollectWmi(List<Finding> findings)
{
    var queries = new[] {
        ("__EventFilter",                "WMI Event Filter"),
        ("CommandLineEventConsumer",     "WMI Command Runner"),
        ("ActiveScriptEventConsumer",    "WMI Script Runner"),
    };

    foreach (var (cls, label) in queries)
    {
        var output = RunCommand("powershell",
            $"-NoProfile -NonInteractive -Command \"Get-CimInstance -Namespace root/subscription -ClassName {cls} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name\"",
            8000);
        foreach (var line in output.Split('\n'))
        {
            var name = line.Trim();
            if (string.IsNullOrEmpty(name) || name == "Name") continue;
            // Skip known legitimate Windows WMI subscriptions
            if (name is "SCM Event Log Filter" or "BVTFilter" or "TSLogonEvents" or "TSLogonFilter") continue;

            findings.Add(new Finding(name,
                $"{label} found — WMI is a hidden auto-run location that most tools miss",
                $"This is almost always malware. Open PowerShell as Admin and run: Get-CimInstance -Namespace root/subscription -ClassName {cls} | Where-Object Name -eq '{name}' | Remove-CimInstance",
                "HIGH", "WMI"));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void ShowNetworkConnections()
{
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Reading network connections...[/]", _ => System.Threading.Thread.Sleep(400));

    try
    {
        var output = RunCommand("netstat", "-ano");
        var pidMap = new Dictionary<int, string>();
        foreach (var proc in Process.GetProcesses())
            try { pidMap[proc.Id] = proc.ProcessName; } catch { }

        AnsiConsole.MarkupLine("[bold mediumpurple1]Connection status guide:[/]");
        AnsiConsole.MarkupLine("[green]Active connection[/]  = currently sending or receiving data");
        AnsiConsole.MarkupLine("[mediumpurple1]Waiting[/]           = listening for incoming connections");
        AnsiConsole.MarkupLine("[yellow]Closing[/]           = connection is shutting down");
        AnsiConsole.WriteLine();

        var table = new Table().BorderColor(Color.MediumPurple1)
            .AddColumn("[bold]Type[/]").AddColumn("[bold]Your Address[/]")
            .AddColumn("[bold]Remote Address[/]").AddColumn("[bold]Status[/]")
            .AddColumn("[bold]Program[/]").AddColumn("[bold]Note[/]");

        foreach (var line in output.Split('\n').Skip(4))
        {
            var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;

            string proto = parts[0], local = parts[1], remote = parts[2];
            string state = parts.Length >= 5 ? parts[3] : "-";
            string pidStr = parts[^1];
            pidMap.TryGetValue(int.TryParse(pidStr, out int pid) ? pid : -1, out string? procName);

            string stateMarkup = state switch
            {
                "ESTABLISHED" => "[green]Active connection[/]",
                "LISTENING"   => "[mediumpurple1]Waiting[/]",
                "TIME_WAIT"   => "[grey]Closing[/]",
                "CLOSE_WAIT"  => "[yellow]Closing (slow)[/]",
                _             => $"[grey]{Markup.Escape(state)}[/]"
            };

            // Check for suspicious ports
            string note = "";
            var remotePort = remote.Contains(':') ? int.TryParse(remote.Split(':')[^1], out int rp) ? rp : 0 : 0;
            if (suspiciousPorts.Contains(remotePort))
                note = $"[red]Port {remotePort} is commonly used by malware[/]";

            string program = string.IsNullOrEmpty(procName)
                ? $"[grey]PID {pidStr}[/]"
                : $"[white]{Markup.Escape(procName)}[/] [grey](PID {pidStr})[/]";

            table.AddRow(Markup.Escape(proto), Markup.Escape(local), Markup.Escape(remote), stateMarkup, program, note);
        }

        AnsiConsole.Write(table);
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[red]Error: {Markup.Escape(ex.Message)}[/]");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void HashFile()
{
    var path = PickFile();
    if (path == null) return;
    if (!File.Exists(path)) { AnsiConsole.MarkupLine($"[red]File not found: {Markup.Escape(path)}[/]"); return; }

    string md5 = "", sha1 = "", sha256 = "";
    double entropy = 0;
    bool hasPe = false;
    string? signer = null;

    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Analysing file...[/]", _ =>
        {
            using var s = File.OpenRead(path);
            md5    = Convert.ToHexString(MD5.HashData(s)).ToLower();    s.Seek(0, SeekOrigin.Begin);
            sha1   = Convert.ToHexString(SHA1.HashData(s)).ToLower();   s.Seek(0, SeekOrigin.Begin);
            sha256 = Convert.ToHexString(SHA256.HashData(s)).ToLower();
            entropy = ComputeEntropy(path);
            hasPe   = HasPeHeader(path);
            signer  = GetAuthenticodeSigner(path);
        });

    string entropyRating = entropy > 7.4 ? "[red]Very high — likely packed/encrypted[/]"
                         : entropy > 6.5 ? "[yellow]Elevated — possibly compressed[/]"
                         : "[green]Normal[/]";
    string signerDisplay = signer != null
        ? (IsTrustedSigner(path) ? $"[green]{Markup.Escape(signer)}[/]" : $"[yellow]{Markup.Escape(signer)} (unknown publisher)[/]")
        : "[grey]Unsigned[/]";
    string peDisplay = hasPe ? "[yellow]Yes — this is an executable program[/]" : "[green]No[/]";

    AnsiConsole.Write(new Panel(new Markup(
        $"[grey]File      :[/] [white]{Markup.Escape(Path.GetFileName(path))}[/]\n" +
        $"[grey]Size      :[/] [white]{new FileInfo(path).Length:N0} bytes[/]\n" +
        $"[grey]Signed by :[/] {signerDisplay}\n" +
        $"[grey]Executable:[/] {peDisplay}\n" +
        $"[grey]Entropy   :[/] {entropyRating}\n\n" +
        $"[grey]MD5       :[/] [white]{md5}[/]\n" +
        $"[grey]SHA1      :[/] [white]{sha1}[/]\n" +
        $"[grey]SHA256    :[/] [white]{sha256}[/]\n\n" +
        $"[grey]To check if this file is known malware, copy the SHA256 above\nand paste it into[/] [white]virustotal.com[/]"
    )).Header("[bold mediumpurple1] File Analysis [/]").BorderColor(Color.MediumPurple1).Padding(2, 1));
}

// ─────────────────────────────────────────────────────────────────────────────
void PrintFindings(List<Finding> findings, string title, bool showInfo = false)
{
    var toShow = showInfo ? findings : findings.Where(f => f.Risk != "INFO").ToList();

    int high   = toShow.Count(f => f.Risk == "HIGH");
    int medium = toShow.Count(f => f.Risk == "MEDIUM");
    int info   = toShow.Count(f => f.Risk == "INFO");

    string summaryText = high > 0
        ? $"[bold red]Threats found! {high} dangerous item(s) require immediate attention.[/]"
        : medium > 0
            ? $"[bold yellow]{medium} suspicious item(s) found. Worth reviewing.[/]"
            : "[bold green]All clear! Nothing suspicious was found.[/]";

    AnsiConsole.Write(new Panel(new Markup(
        summaryText + (info > 0 ? $"\n[grey]{info} normal startup entries also shown below.[/]" : "")
    )).Header($"[bold] {title} Results [/]")
      .BorderColor(high > 0 ? Color.Red : medium > 0 ? Color.Yellow : Color.Green)
      .Padding(2, 0));

    if (toShow.Count == 0) return;

    AnsiConsole.WriteLine();
    var table = new Table().BorderColor(Color.MediumPurple1)
        .AddColumn(new TableColumn("[bold]Level[/]").Width(10))
        .AddColumn(new TableColumn("[bold]What was found[/]").Width(28))
        .AddColumn(new TableColumn("[bold]Why it's flagged[/]"))
        .AddColumn(new TableColumn("[bold]What to do[/]"));

    foreach (var f in toShow.OrderBy(f => f.Risk switch { "HIGH" => 0, "MEDIUM" => 1, "LOW" => 2, _ => 3 }))
    {
        string riskMarkup = f.Risk switch
        {
            "HIGH"   => "[bold red]DANGER[/]",
            "MEDIUM" => "[bold yellow]WARNING[/]",
            "LOW"    => "[bold orange3]UNUSUAL[/]",
            _        => "[grey]INFO[/]"
        };
        string actionMarkup = f.Risk switch
        {
            "HIGH"   => $"[red]{Markup.Escape(f.Action)}[/]",
            "MEDIUM" => $"[yellow]{Markup.Escape(f.Action)}[/]",
            _        => $"[grey]{Markup.Escape(f.Action)}[/]"
        };
        string display = f.Item.Length > 30 ? "..." + f.Item[^27..] : f.Item;
        table.AddRow(riskMarkup, Markup.Escape(display), Markup.Escape(f.Reason), actionMarkup);
    }

    AnsiConsole.Write(table);
}

// ─────────────────────────────────────────────────────────────────────────────
void BlockConnection()
{
    if (!isAdmin)
    {
        AnsiConsole.MarkupLine("[yellow]Administrator rights required to block connections. Right-click the exe and choose 'Run as administrator'.[/]");
        return;
    }

    // Collect active remote IPs from netstat
    var output = RunCommand("netstat", "-ano");
    var pidMap = new Dictionary<int, string>();
    foreach (var proc in Process.GetProcesses())
        try { pidMap[proc.Id] = proc.ProcessName; } catch { }

    var connections = new List<(string ip, string display)>();
    var seenIps = new HashSet<string>();

    foreach (var line in output.Split('\n').Skip(4))
    {
        var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 4) continue;
        string remote = parts[2];
        string state  = parts.Length >= 5 ? parts[3] : "";
        string pidStr = parts[^1];

        // Only show ESTABLISHED connections to real remote IPs
        if (state != "ESTABLISHED") continue;
        if (remote.StartsWith("0.0.0.0") || remote.StartsWith("127.") || remote.StartsWith("[::")) continue;

        // Extract IP without port
        string ip = remote.Contains(':') ? string.Join(":", remote.Split(':')[..^1]).Trim('[', ']') : remote;
        if (!seenIps.Add(ip)) continue;

        pidMap.TryGetValue(int.TryParse(pidStr, out int pid) ? pid : -1, out string? procName);
        string label = $"{ip}  [{(procName ?? $"PID {pidStr}")}]  {remote.Split(':')[^1]}";
        connections.Add((ip, label));
    }

    if (connections.Count == 0)
    {
        AnsiConsole.MarkupLine("[green]No active outbound connections found right now.[/]");
        return;
    }

    AnsiConsole.MarkupLine("[bold mediumpurple1]Active connections on your machine:[/]");
    AnsiConsole.MarkupLine("[grey]Blocking will add a Windows Firewall rule that stops all traffic to/from that IP.[/]\n");

    var choices = connections.Select(c => c.display).ToList();
    choices.Add("Cancel");

    var selected = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[mediumpurple1]Which connection do you want to block?[/]")
            .HighlightStyle(Style.Parse("bold mediumpurple1"))
            .AddChoices(choices)
    );

    if (selected == "Cancel") return;

    var (targetIp, _) = connections.First(c => c.display == selected);
    string ruleName = $"Robb-IT Block {targetIp}";

    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Applying firewall rule...[/]", _ =>
        {
            RunCommand("netsh", $"advfirewall firewall add rule name=\"{ruleName}\" dir=in  action=block remoteip={targetIp} enable=yes", 8000);
            RunCommand("netsh", $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={targetIp} enable=yes", 8000);
        });

    AnsiConsole.MarkupLine($"[green]✓ Blocked! All traffic to/from [bold]{Markup.Escape(targetIp)}[/] is now blocked.[/]");
    AnsiConsole.MarkupLine($"[grey]Rule name: \"{Markup.Escape(ruleName)}\" — visible in Windows Firewall settings.[/]");
}

// ─────────────────────────────────────────────────────────────────────────────
void ManageBlockedIPs()
{
    if (!isAdmin)
    {
        AnsiConsole.MarkupLine("[yellow]Administrator rights required. Right-click the exe and choose 'Run as administrator'.[/]");
        return;
    }

    // Find all Robb-IT block rules
    var output = RunCommand("netsh", "advfirewall firewall show rule name=all", 15000);
    var rules = new List<string>();
    string? currentName = null;
    foreach (var line in output.Split('\n'))
    {
        var trimmed = line.Trim();
        if (trimmed.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
        {
            currentName = trimmed["Rule Name:".Length..].Trim();
            if (currentName.StartsWith("Robb-IT Block ", StringComparison.OrdinalIgnoreCase))
            {
                var ip = currentName["Robb-IT Block ".Length..].Trim();
                if (!rules.Contains(ip))
                    rules.Add(ip);
            }
        }
    }

    if (rules.Count == 0)
    {
        AnsiConsole.MarkupLine("[green]No IPs are currently blocked by Robb-IT.[/]");
        return;
    }

    AnsiConsole.MarkupLine($"[bold mediumpurple1]Currently blocked IPs ({rules.Count}):[/]\n");
    var table = new Table().BorderColor(Color.MediumPurple1)
        .AddColumn("[bold]Blocked IP[/]")
        .AddColumn("[bold]Firewall Rule[/]");
    foreach (var ip in rules)
        table.AddRow(Markup.Escape(ip), Markup.Escape($"Robb-IT Block {ip}"));
    AnsiConsole.Write(table);
    AnsiConsole.WriteLine();

    var choices = rules.Select(ip => $"Unblock  {ip}").ToList();
    choices.Add("Unblock ALL");
    choices.Add("Cancel");

    var selected = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[mediumpurple1]Select an IP to unblock, or cancel:[/]")
            .HighlightStyle(Style.Parse("bold mediumpurple1"))
            .AddChoices(choices)
    );

    if (selected == "Cancel") return;

    var toRemove = selected == "Unblock ALL" ? rules : new List<string> { selected["Unblock  ".Length..] };

    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Removing firewall rules...[/]", _ =>
        {
            foreach (var ip in toRemove)
            {
                string ruleName = $"Robb-IT Block {ip}";
                RunCommand("netsh", $"advfirewall firewall delete rule name=\"{ruleName}\"", 8000);
            }
        });

    AnsiConsole.MarkupLine($"[green]✓ Unblocked {toRemove.Count} IP(s) — firewall rules removed.[/]");
}

// ─────────────────────────────────────────────────────────────────────────────
void LiveTrafficMonitor()
{
    AnsiConsole.Write(new Panel(new Markup(
        "[bold white]Real-time connection monitor[/]\n" +
        "[grey]Watches for new network connections every 2 seconds.\n" +
        "Flags suspicious ports, unknown processes, and AppData connections.\n\n" +
        "Press [bold]Q[/] at any time to stop.[/]"
    )).Header("[bold mediumpurple1] Live Traffic Monitor [/]")
      .BorderColor(Color.MediumPurple1).Padding(2, 0));
    AnsiConsole.WriteLine();

    // Snapshot previous connections so we only show NEW ones
    var known = GetCurrentConnections();
    int tick = 0;

    AnsiConsole.MarkupLine("[grey]Monitoring... (press Q to stop)[/]\n");

    while (true)
    {
        // Non-blocking key check
        if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Q)
            break;

        System.Threading.Thread.Sleep(2000);
        tick++;

        var current = GetCurrentConnections();
        var newConns = current.Where(c => !known.ContainsKey(c.Key)).ToList();
        var closed   = known.Where(k => !current.ContainsKey(k.Key)).Select(k => k.Key).ToList();

        // Print timestamp every 10 ticks even if quiet
        if (tick % 10 == 0 && newConns.Count == 0)
            AnsiConsole.MarkupLine($"[grey]{DateTime.Now:HH:mm:ss}  —  no new connections[/]");

        foreach (var conn in newConns)
        {
            var c = conn.Value;
            string timeStamp = $"[grey]{DateTime.Now:HH:mm:ss}[/]";
            string arrow = "[mediumpurple1]▶[/]";

            // Determine alert level
            bool isSuspiciousPort  = suspiciousPorts.Contains(c.RemotePort);
            bool isAppData         = c.ProcPath.Contains("\\appdata\\", StringComparison.OrdinalIgnoreCase)
                                  && !IsInLegitPath(c.ProcPath);
            bool isTemp            = c.ProcPath.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase);
            bool isSuspiciousProc  = knownMalware.Any(m => MatchesMalware(c.ProcName, m));

            string levelMarkup, noteMarkup;
            if (isSuspiciousProc || isTemp)
            {
                levelMarkup = "[bold red]DANGER [/]";
                noteMarkup  = isTemp ? "[red]Running from temp folder![/]"
                                     : "[red]Process name matches known malware![/]";
            }
            else if (isSuspiciousPort || isAppData)
            {
                levelMarkup = "[bold yellow]WARNING[/]";
                noteMarkup  = isSuspiciousPort ? $"[yellow]Port {c.RemotePort} used by malware/RATs[/]"
                                               : "[yellow]Process running from hidden AppData folder[/]";
            }
            else
            {
                levelMarkup = "[grey]  new  [/]";
                noteMarkup  = "";
            }

            string proc = string.IsNullOrEmpty(c.ProcName)
                ? $"[grey]PID {c.Pid}[/]"
                : $"[white]{Markup.Escape(c.ProcName)}[/]";

            AnsiConsole.MarkupLine(
                $"{timeStamp} {levelMarkup} {arrow} " +
                $"{proc}  [grey]→[/]  [white]{Markup.Escape(c.Remote)}[/]" +
                (string.IsNullOrEmpty(noteMarkup) ? "" : $"  {noteMarkup}")
            );
        }

        foreach (var key in closed)
        {
            var c = known[key];
            AnsiConsole.MarkupLine(
                $"[grey]{DateTime.Now:HH:mm:ss}   closed   {Markup.Escape(c.ProcName)}  →  {Markup.Escape(c.Remote)}[/]"
            );
        }

        known = current;
    }

    AnsiConsole.MarkupLine("\n[grey]Monitor stopped.[/]");
}

// Snapshot of current ESTABLISHED connections keyed by "proto|local|remote|pid"
Dictionary<string, (string Remote, int RemotePort, string ProcName, string ProcPath, int Pid)>
    GetCurrentConnections()
{
    var result = new Dictionary<string, (string, int, string, string, int)>();
    var pidToPath = new Dictionary<int, (string name, string path)>();
    foreach (var p in Process.GetProcesses())
        try { pidToPath[p.Id] = (p.ProcessName, p.MainModule?.FileName ?? ""); } catch { }

    var output = RunCommand("netstat", "-ano");
    foreach (var line in output.Split('\n').Skip(4))
    {
        var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 5) continue;
        if (parts[3] != "ESTABLISHED") continue;

        string proto  = parts[0];
        string local  = parts[1];
        string remote = parts[2];
        string pidStr = parts[4];
        if (!int.TryParse(pidStr, out int pid)) continue;

        int remotePort = int.TryParse(remote.Split(':')[^1], out int rp) ? rp : 0;
        pidToPath.TryGetValue(pid, out var procInfo);

        string key = $"{proto}|{local}|{remote}|{pid}";
        result.TryAdd(key, (remote, remotePort, procInfo.name ?? "", procInfo.path ?? "", pid));
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
void DpiBypass()
{
    if (!isAdmin)
    {
        AnsiConsole.MarkupLine("[yellow]Administrator rights required. Right-click the exe → Run as administrator.[/]");
        return;
    }

    bool active = proxyTokenSource != null && !proxyTokenSource.IsCancellationRequested;
    string statusLine = active
        ? "[green]● DPI Bypass is ACTIVE[/]  — proxy on [white]127.0.0.1:8881[/], DNS on [white]1.1.1.1 (DoH)[/]"
        : "[grey]○ DPI Bypass is OFF[/]";

    AnsiConsole.Write(new Panel(new Markup(
        $"{statusLine}\n\n" +
        "[bold white]How it works (no external programs needed):[/]\n" +
        "[grey]1.[/] [white]DNS → Cloudflare 1.1.1.1 over HTTPS[/] [grey]— defeats DNS-based blocking\n" +
        "[grey]2.[/] [white]Local TCP proxy on port 8881[/] [grey]— intercepts your browser traffic\n" +
        "[grey]3.[/] [white]TLS ClientHello fragmentation[/] [grey]— splits the packet DPI reads\n" +
        "   to detect & block sites, so it can't see the full SNI field[/]"
    )).Header("[bold mediumpurple1] DPI Bypass [/]")
      .BorderColor(active ? Color.Green : Color.MediumPurple1).Padding(2, 0));
    AnsiConsole.WriteLine();

    var choices = new List<string>();
    if (!active) choices.Add("Start DPI Bypass");
    else         choices.Add("Stop DPI Bypass");
    choices.Add("Flush DNS Cache");
    choices.Add("Cancel");

    var choice = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[mediumpurple1]What do you want to do?[/]")
            .HighlightStyle(Style.Parse("bold mediumpurple1"))
            .AddChoices(choices)
    );

    switch (choice)
    {
        case "Start DPI Bypass": StartDpiBypass(); break;
        case "Stop DPI Bypass":  StopDpiBypass();  break;
        case "Flush DNS Cache":  FlushDns();        break;
    }
}

void StartDpiBypass()
{
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Starting DPI bypass...[/]", ctx =>
        {
            ApplyDnsBypass();
            proxyTokenSource = new CancellationTokenSource();
            var proxyTask = Task.Run(() => RunDpiProxy(proxyTokenSource.Token));
            System.Threading.Thread.Sleep(600); // let proxy bind
            SetSystemProxy("127.0.0.1:8881");
        });

    AnsiConsole.MarkupLine("[green]✓ DNS set to Cloudflare 1.1.1.1 with DoH[/]");
    AnsiConsole.MarkupLine("[green]✓ DPI bypass proxy started on 127.0.0.1:8881[/]");
    AnsiConsole.MarkupLine("[green]✓ System proxy configured — browsers will use the bypass[/]");
    AnsiConsole.MarkupLine("\n[grey]Keep Robb-IT open while the bypass is running.[/]");
    AnsiConsole.MarkupLine("[grey]Go back to menu → DPI Bypass → Stop when you are done.[/]");
}

void StopDpiBypass()
{
    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Stopping DPI bypass...[/]", _ =>
        {
            proxyTokenSource?.Cancel();
            proxyTokenSource = null;
            RemoveSystemProxy();
            RestoreDns();
            System.Threading.Thread.Sleep(400);
        });

    AnsiConsole.MarkupLine("[green]✓ Proxy stopped[/]");
    AnsiConsole.MarkupLine("[green]✓ System proxy removed[/]");
    AnsiConsole.MarkupLine("[green]✓ DNS restored[/]");
}

// ── DNS helpers ───────────────────────────────────────────────────────────────
void ApplyDnsBypass()
{
    var ifOutput = RunCommand("netsh", "interface show interface", 5000);
    foreach (var line in ifOutput.Split('\n').Skip(3))
    {
        var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 4) continue;
        if (!parts[1].Equals("Connected", StringComparison.OrdinalIgnoreCase)) continue;
        var ifName = string.Join(" ", parts[3..]);

        // Save original DNS
        var orig = RunCommand("netsh", $"interface ipv4 show dnsservers \"{ifName}\"", 5000);
        File.AppendAllText(Path.Combine(Path.GetTempPath(), "robbIT_orig_dns.txt"), $"{ifName}\n{orig}\n---\n");

        RunCommand("netsh", $"interface ipv4 set dnsservers \"{ifName}\" static 1.1.1.1 primary validate=no", 5000);
        RunCommand("netsh", $"interface ipv4 add dnsservers \"{ifName}\" 8.8.8.8 index=2 validate=no", 5000);
    }
    RunCommand("powershell",
        "-NoProfile -NonInteractive -Command \"" +
        "Add-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AutoUpgrade $true -AllowFallbackToUdp $false -ErrorAction SilentlyContinue;" +
        "Add-DnsClientDohServerAddress -ServerAddress '8.8.8.8' -DohTemplate 'https://dns.google/dns-query' -AutoUpgrade $true -AllowFallbackToUdp $false -ErrorAction SilentlyContinue\"",
        10000);
    RunCommand("ipconfig", "/flushdns", 5000);
}

void RestoreDns()
{
    var savePath = Path.Combine(Path.GetTempPath(), "robbIT_orig_dns.txt");
    var ifOutput = RunCommand("netsh", "interface show interface", 5000);
    foreach (var line in ifOutput.Split('\n').Skip(3))
    {
        var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 4) continue;
        if (!parts[1].Equals("Connected", StringComparison.OrdinalIgnoreCase)) continue;
        var ifName = string.Join(" ", parts[3..]);
        RunCommand("netsh", $"interface ipv4 set dnsservers \"{ifName}\" dhcp", 5000);
    }
    RunCommand("ipconfig", "/flushdns", 5000);
    if (File.Exists(savePath)) File.Delete(savePath);
}

void FlushDns()
{
    RunCommand("ipconfig", "/flushdns", 5000);
    AnsiConsole.MarkupLine("[green]✓ DNS cache cleared.[/]");
}

void SetSystemProxy(string proxy)
{
    RunCommand("powershell",
        $"-NoProfile -NonInteractive -Command \"" +
        $"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1 -Type DWord;" +
        $"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value '{proxy}';" +
        $"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyOverride -Value 'localhost;127.*'\"",
        8000);
}

void RemoveSystemProxy()
{
    RunCommand("powershell",
        "-NoProfile -NonInteractive -Command \"" +
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0 -Type DWord\"",
        8000);
}

// ── DPI Proxy ─────────────────────────────────────────────────────────────────
async Task RunDpiProxy(CancellationToken ct)
{
    var listener = new TcpListener(IPAddress.Loopback, 8881);
    listener.Start();
    try
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleProxyClient(client, ct), CancellationToken.None);
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }
    finally { listener.Stop(); }
}

async Task HandleProxyClient(TcpClient client, CancellationToken ct)
{
    client.NoDelay = true;
    using var _ = client;
    try
    {
        using var clientStream = client.GetStream();
        var buf = new byte[8192];
        int read = await clientStream.ReadAsync(buf, ct);
        if (read == 0) return;

        var header = Encoding.ASCII.GetString(buf, 0, read);
        var firstLine = header.Split('\n')[0].Trim();

        // Only handle CONNECT (HTTPS tunnel)
        if (!firstLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase)) return;

        var hostPort = firstLine.Split(' ')[1];
        int lastColon = hostPort.LastIndexOf(':');
        string host = hostPort[..lastColon];
        if (!int.TryParse(hostPort[(lastColon + 1)..], out int port)) port = 443;

        // Strip IPv6 brackets
        host = host.Trim('[', ']');

        using var server = new TcpClient { NoDelay = true };
        await server.ConnectAsync(host, port, ct);
        using var serverStream = server.GetStream();

        // Tell client tunnel is open
        var ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        await clientStream.WriteAsync(ok, ct);

        // Read first chunk from client — should be TLS ClientHello
        var tlsBuf = new byte[16384];
        int tlsRead = await clientStream.ReadAsync(tlsBuf, ct);
        if (tlsRead == 0) return;

        // Fragment TLS ClientHello: send 1 byte, tiny delay, then the rest
        // DPI reassembles TCP for analysis — by splitting across segments it
        // sees an incomplete record and can't identify the SNI / block the site
        if (tlsRead > 5 && tlsBuf[0] == 0x16) // TLS Handshake record
        {
            await serverStream.WriteAsync(tlsBuf.AsMemory(0, 1), ct);
            await Task.Delay(1, ct);
            await serverStream.WriteAsync(tlsBuf.AsMemory(1, tlsRead - 1), ct);
        }
        else
        {
            await serverStream.WriteAsync(tlsBuf.AsMemory(0, tlsRead), ct);
        }

        // Bidirectional pipe for rest of session
        var up   = ProxyCopy(clientStream, serverStream, ct);
        var down = ProxyCopy(serverStream, clientStream, ct);
        await Task.WhenAny(up, down);
    }
    catch { }
}

async Task ProxyCopy(NetworkStream from, NetworkStream to, CancellationToken ct)
{
    var buf = new byte[65536];
    try
    {
        int n;
        while ((n = await from.ReadAsync(buf, ct)) > 0)
            await to.WriteAsync(buf.AsMemory(0, n), ct);
    }
    catch { }
}

// ─────────────────────────────────────────────────────────────────────────────
void DeepFileScan()
{
    var path = PickFile();
    if (path == null) return;
    if (!File.Exists(path)) { AnsiConsole.MarkupLine($"[red]File not found: {Markup.Escape(path)}[/]"); return; }

    var info = new FileInfo(path);
    string md5 = "", sha1 = "", sha256 = "";
    double entropy = 0;
    bool hasPe = false;
    string? signer = null;
    string fileType = "Unknown";
    var suspiciousStrings = new List<string>();
    var embeddedUrls      = new List<string>();
    int riskScore = 0;
    var riskReasons = new List<string>();

    AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("mediumpurple1"))
        .Start("[mediumpurple1]Deep scanning file...[/]", _ =>
        {
            // Hashes
            using var s = File.OpenRead(path);
            md5    = Convert.ToHexString(MD5.HashData(s)).ToLower();    s.Seek(0, SeekOrigin.Begin);
            sha1   = Convert.ToHexString(SHA1.HashData(s)).ToLower();   s.Seek(0, SeekOrigin.Begin);
            sha256 = Convert.ToHexString(SHA256.HashData(s)).ToLower(); s.Seek(0, SeekOrigin.Begin);

            // Read raw bytes
            var bytes = new byte[Math.Min(info.Length, 2 * 1024 * 1024)]; // max 2MB
            int totalRead = s.Read(bytes, 0, bytes.Length);

            // Magic bytes / file type
            fileType = DetectFileType(bytes);
            hasPe    = totalRead >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A;

            // Entropy
            entropy = ComputeEntropy(path);

            // Signature
            signer = GetAuthenticodeSigner(path);

            // Extract readable strings (min 5 chars)
            var extracted = ExtractStrings(bytes, totalRead, 5);

            // Suspicious API / technique strings — specific enough to avoid .NET runtime noise
            var suspPatterns = new[] {
                "VirtualAlloc","WriteProcessMemory","CreateRemoteThread","ShellExecuteA","ShellExecuteW",
                "WinExec","URLDownloadToFile","WSAStartup",
                "RegSetValue","RegCreateKey","CreateService",
                "cmd.exe /c","cmd.exe /k","powershell -","powershell.exe -",
                "frombase64string","invoke-expression","invoke-webrequest",
                "-encodedcommand","-windowstyle hidden","-executionpolicy bypass",
                "certutil -decode","certutil -urlcache","bitsadmin /transfer",
                "mshta.exe","wscript.exe","cscript.exe","rundll32.exe",
                "net user /add","net localgroup administrators",
                "whoami /all","mimikatz","sekurlsa","lsass.exe",
                ":\\temp\\",":\\users\\public\\",
            };

            // Strings to ignore — .NET runtime internals, framework names
            var ignorePatterns = new[] {
                "System.","Microsoft.","Windows.","runtime.","netstandard",
                ".resources",".dll",".pdb",".xml","Namespace","Assembly",
                "PublicKey","Culture=","Version=","processorArchitecture",
            };

            foreach (var str in extracted)
            {
                var trimmed = str.Trim();

                // Skip if it looks like a .NET framework string
                bool isFramework = ignorePatterns.Any(p => trimmed.Contains(p, StringComparison.OrdinalIgnoreCase));
                if (isFramework) goto checkUrl;

                foreach (var pat in suspPatterns)
                    if (trimmed.Contains(pat, StringComparison.OrdinalIgnoreCase)
                        && !suspiciousStrings.Contains(trimmed) && trimmed.Length < 120)
                    { suspiciousStrings.Add(trimmed); break; }

                checkUrl:
                // Pull out URLs (skip localhost/internal)
                if ((trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                     trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                     && !trimmed.Contains("localhost") && !trimmed.Contains("127.0.0.")
                     && trimmed.Length < 200 && !embeddedUrls.Contains(trimmed))
                    embeddedUrls.Add(trimmed);
            }

            // ── Risk Scoring ──────────────────────────────────────────────
            var ext  = Path.GetExtension(path);
            var name = Path.GetFileName(path).ToLower();
            var dir  = (Path.GetDirectoryName(path) ?? "").ToLower();

            if (hasPe && documentExts.Contains(ext))
            { riskScore += 40; riskReasons.Add("Document file contains executable code (PE header)"); }

            var nameParts = name.Split('.');
            if (nameParts.Length >= 3 && dangerousExts.Contains("." + nameParts[^1]) && documentExts.Contains("." + nameParts[^2]))
            { riskScore += 35; riskReasons.Add("Double extension — fake document that runs as a program"); }

            if (info.Attributes.HasFlag(FileAttributes.Hidden) && dangerousExts.Contains(ext))
            { riskScore += 15; riskReasons.Add("File is hidden from view"); }

            if (dir.Contains("\\temp\\") || dir.StartsWith(tempPath))
            { riskScore += 25; riskReasons.Add("Located in a temporary folder"); }
            else if (dir.Contains("\\appdata\\") && !IsInLegitPath(dir))
            { riskScore += 15; riskReasons.Add("Located in a hidden AppData folder"); }

            if (hasPe && signer == null)
            { riskScore += 20; riskReasons.Add("Unsigned executable — no publisher certificate"); }
            else if (hasPe && !IsTrustedSigner(path))
            { riskScore += 10; riskReasons.Add("Signed by an unknown publisher"); }

            if (entropy > 7.4)
            { riskScore += 25; riskReasons.Add($"Very high entropy ({entropy:F1}/8.0) — likely packed or encrypted"); }
            else if (entropy > 6.5)
            { riskScore += 10; riskReasons.Add($"Elevated entropy ({entropy:F1}/8.0) — possibly compressed"); }

            foreach (var m in knownMalware)
                if (MatchesMalware(name, m))
                { riskScore += 50; riskReasons.Add($"File name matches known malware: \"{m}\""); break; }

            if (suspiciousStrings.Count > 0)
            { int add = Math.Min(suspiciousStrings.Count * 5, 25); riskScore += add; riskReasons.Add($"{suspiciousStrings.Count} suspicious string(s) found inside the file"); }

            if (embeddedUrls.Count > 3)
            { riskScore += 10; riskReasons.Add($"{embeddedUrls.Count} embedded URLs found"); }

            riskScore = Math.Min(riskScore, 100);
        });

    // ── Display ───────────────────────────────────────────────────────────────
    string scoreColor = riskScore >= 70 ? "red" : riskScore >= 35 ? "yellow" : "green";
    string scoreLabel = riskScore >= 70 ? "HIGH RISK" : riskScore >= 35 ? "SUSPICIOUS" : "LIKELY SAFE";
    string signerDisplay = signer != null
        ? (IsTrustedSigner(path) ? $"[green]{Markup.Escape(signer)}[/]" : $"[yellow]{Markup.Escape(signer)} (unknown)[/]")
        : "[grey]Unsigned[/]";

    AnsiConsole.WriteLine();
    AnsiConsole.Write(new Panel(new Markup(
        $"[grey]File     :[/] [white]{Markup.Escape(info.Name)}[/]\n" +
        $"[grey]Size     :[/] [white]{info.Length:N0} bytes  ({info.Length / 1024.0:F1} KB)[/]\n" +
        $"[grey]Type     :[/] [white]{Markup.Escape(fileType)}[/]\n" +
        $"[grey]Modified :[/] [white]{info.LastWriteTime:yyyy-MM-dd HH:mm:ss}[/]\n" +
        $"[grey]Signed by:[/] {signerDisplay}\n" +
        $"[grey]Entropy  :[/] [white]{entropy:F2} / 8.0[/]\n\n" +
        $"[grey]MD5      :[/] [white]{md5}[/]\n" +
        $"[grey]SHA1     :[/] [white]{sha1}[/]\n" +
        $"[grey]SHA256   :[/] [white]{sha256}[/]"
    )).Header("[bold mediumpurple1] File Info [/]").BorderColor(Color.MediumPurple1).Padding(2, 1));

    // Risk score panel
    AnsiConsole.Write(new Panel(new Markup(
        $"[bold {scoreColor}]  {riskScore}/100 — {scoreLabel}[/]\n\n" +
        (riskReasons.Count > 0
            ? string.Join("\n", riskReasons.Select(r => $"[{scoreColor}]•[/] {Markup.Escape(r)}"))
            : "[green]No threat indicators found.[/]")
    )).Header("[bold mediumpurple1] Risk Score [/]")
      .BorderColor(riskScore >= 70 ? Color.Red : riskScore >= 35 ? Color.Yellow : Color.Green)
      .Padding(2, 1));

    // Suspicious strings
    if (suspiciousStrings.Count > 0)
    {
        AnsiConsole.Write(new Panel(new Markup(
            string.Join("\n", suspiciousStrings.Take(15).Select(s => $"[yellow]›[/] [grey]{Markup.Escape(s.Trim())}[/]"))
            + (suspiciousStrings.Count > 15 ? $"\n[grey]  ... and {suspiciousStrings.Count - 15} more[/]" : "")
        )).Header("[bold yellow] Suspicious Strings Found [/]").BorderColor(Color.Yellow).Padding(2, 1));
    }

    // Embedded URLs
    if (embeddedUrls.Count > 0)
    {
        AnsiConsole.Write(new Panel(new Markup(
            string.Join("\n", embeddedUrls.Take(10).Select(u => $"[mediumpurple1]›[/] [white]{Markup.Escape(u)}[/]"))
            + (embeddedUrls.Count > 10 ? $"\n[grey]  ... and {embeddedUrls.Count - 10} more[/]" : "")
        )).Header("[bold mediumpurple1] Embedded URLs [/]").BorderColor(Color.MediumPurple1).Padding(2, 1));
    }

    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[grey]Copy the SHA256 above and check it on[/] [white]virustotal.com[/] [grey]to see results from 70+ antivirus engines.[/]");
    if (AnsiConsole.Confirm("[mediumpurple1]Open this file on VirusTotal now?[/]"))
    {
        Process.Start(new ProcessStartInfo($"https://www.virustotal.com/gui/file/{sha256}") { UseShellExecute = true });
        AnsiConsole.MarkupLine("[green]✓ Opened in your browser.[/]");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
string? PickFolder()
{
    var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    var locations = new Dictionary<string, string>
    {
        ["Desktop"]       = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        ["Downloads"]     = Path.Combine(profile, "Downloads"),
        ["Documents"]     = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        ["Pictures"]      = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
        ["AppData"]       = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        ["Temp"]          = Path.GetTempPath(),
        ["C:\\"]          = @"C:\",
        ["Type a path..."]= "",
    };

    var choice = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[mediumpurple1]Which folder?[/]")
            .HighlightStyle(Style.Parse("bold mediumpurple1"))
            .AddChoices(locations.Keys)
    );

    if (choice == "Type a path...")
    {
        var raw = AnsiConsole.Ask<string>("[mediumpurple1]Folder path:[/]");
        return ResolvePath(raw);
    }
    return locations[choice];
}

string? PickFile()
{
    var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    var locations = new Dictionary<string, string>
    {
        ["Desktop"]       = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        ["Downloads"]     = Path.Combine(profile, "Downloads"),
        ["Documents"]     = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        ["Temp"]          = Path.GetTempPath(),
        ["Type a path..."]= "",
    };

    var folderChoice = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[mediumpurple1]Which folder is the file in?[/]")
            .HighlightStyle(Style.Parse("bold mediumpurple1"))
            .AddChoices(locations.Keys)
    );

    string folder;
    if (folderChoice == "Type a path...")
    {
        var raw = AnsiConsole.Ask<string>("[mediumpurple1]Full file path:[/]");
        return ResolvePath(raw);
    }
    folder = locations[folderChoice];

    // List files in that folder
    string[] files;
    try { files = Directory.GetFiles(folder).OrderByDescending(File.GetLastWriteTime).Take(50).ToArray(); }
    catch { files = Array.Empty<string>(); }

    if (files.Length == 0)
    {
        AnsiConsole.MarkupLine("[yellow]No files found in that folder.[/]");
        return null;
    }

    var fileNames = files.Select(Path.GetFileName).ToList();
    fileNames.Add("Type a path...");

    var picked = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[mediumpurple1]Select a file:[/]")
            .HighlightStyle(Style.Parse("bold mediumpurple1"))
            .PageSize(15)
            .AddChoices(fileNames)
    );

    if (picked == "Type a path...")
    {
        var raw = AnsiConsole.Ask<string>("[mediumpurple1]Full file path:[/]");
        return ResolvePath(raw);
    }
    return Path.Combine(folder, picked);
}

string DetectFileType(byte[] bytes)
{
    if (bytes.Length < 4) return "Unknown";
    if (bytes[0] == 0x4D && bytes[1] == 0x5A) return "Windows Executable (PE)";
    if (bytes[0] == 0x50 && bytes[1] == 0x4B && bytes[2] == 0x03 && bytes[3] == 0x04) return "ZIP / Office (OOXML) / JAR";
    if (bytes[0] == 0x25 && bytes[1] == 0x50 && bytes[2] == 0x44 && bytes[3] == 0x46) return "PDF Document";
    if (bytes[0] == 0xD0 && bytes[1] == 0xCF && bytes[2] == 0x11 && bytes[3] == 0xE0) return "OLE2 (Word/Excel/PowerPoint)";
    if (bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46) return "ELF Executable (Linux)";
    if (bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF) return "JPEG Image";
    if (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47) return "PNG Image";
    if (bytes[0] == 0x47 && bytes[1] == 0x49 && bytes[2] == 0x46) return "GIF Image";
    if (bytes[0] == 0x37 && bytes[1] == 0x7A && bytes[2] == 0xBC && bytes[3] == 0xAF) return "7-Zip Archive";
    if (bytes[0] == 0x52 && bytes[1] == 0x61 && bytes[2] == 0x72 && bytes[3] == 0x21) return "RAR Archive";
    if (bytes[0] == 0xCA && bytes[1] == 0xFE && bytes[2] == 0xBA && bytes[3] == 0xBE) return "Java Class File";
    return "Unknown / Binary";
}

List<string> ExtractStrings(byte[] bytes, int length, int minLen)
{
    var results = new List<string>();
    var current = new System.Text.StringBuilder();
    for (int i = 0; i < length; i++)
    {
        byte b = bytes[i];
        if (b >= 0x20 && b < 0x7F)
            current.Append((char)b);
        else
        {
            if (current.Length >= minLen) results.Add(current.ToString());
            current.Clear();
        }
    }
    if (current.Length >= minLen) results.Add(current.ToString());
    return results;
}

// ─────────────────────────────────────────────────────────────────────────────
void ExportReport()
{
    var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    var file = Path.Combine(desktop, $"RobbIT_Report_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
    var sb = new System.Text.StringBuilder();

    sb.AppendLine("═══════════════════════════════════════════════════════════");
    sb.AppendLine("  Robb-IT Security Report");
    sb.AppendLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
    sb.AppendLine($"  Machine:   {Environment.MachineName}");
    sb.AppendLine("═══════════════════════════════════════════════════════════\n");

    foreach (var risk in new[] { "HIGH", "MEDIUM", "LOW", "INFO" })
    {
        var group = lastFindings.Where(f => f.Risk == risk).ToList();
        if (group.Count == 0) continue;
        sb.AppendLine($"[{risk}] ─────────────────────────────────────────");
        foreach (var f in group)
        {
            sb.AppendLine($"  Item   : {f.Item}");
            sb.AppendLine($"  Reason : {f.Reason}");
            sb.AppendLine($"  Action : {f.Action}");
            sb.AppendLine();
        }
    }

    File.WriteAllText(file, sb.ToString());
    AnsiConsole.MarkupLine($"[green]✓ Report saved to Desktop: {Path.GetFileName(file)}[/]");
}

// ─────────────────────────────────────────────────────────────────────────────
string[] ParseCsv(string line)
{
    var result = new List<string>();
    bool inQuotes = false;
    var current = new System.Text.StringBuilder();
    foreach (char c in line)
    {
        if (c == '"') { inQuotes = !inQuotes; }
        else if (c == ',' && !inQuotes) { result.Add(current.ToString()); current.Clear(); }
        else current.Append(c);
    }
    result.Add(current.ToString());
    return result.ToArray();
}

// ── Types ───────────────────────────────────────────────────────────────────
record Finding(string Item, string Reason, string Action, string Risk, string Category = "");
